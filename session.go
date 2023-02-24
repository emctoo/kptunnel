// -*- coding: utf-8 -*-
package kptunnel

import (
	"container/list"
	"container/ring"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"bytes"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type Lock struct {
	mutex sync.Mutex
	owner string
}

func (lock *Lock) get(name string) {
	lock.mutex.Lock()
	lock.owner = name
}

func (lock *Lock) rel() {
	lock.owner = ""
	lock.mutex.Unlock()
}

var VerboseFlag = false

var DebugFlag = false

func IsDebug() bool {
	return DebugFlag
}

type Forward struct {
	IsReverse bool
	Src       Host
	Dest      Host
}

func (info *Forward) String() string {
	return fmt.Sprintf("Forward(reverse: %t, %s => %s)", info.IsReverse, info.Src.String(), info.Dest.String())
}

// control parameters for tunnel
type TunnelParam struct {
	// common password for session authentication
	Pass *string
	// セッションのモード
	Mode string
	// 接続可能な IP パターン。
	// nil の場合、 IP 制限しない。
	MaskedIP *MaskIP
	// セッションの通信を暗号化するパスワード
	EncPass *string
	// セッションの通信を暗号化する通信数。
	// -1: 常に暗号化
	//  0: 暗号化しない
	//  N: 残り N 回の通信を暗号化する
	EncCount int
	// 無通信を避けるための接続確認の間隔 (ミリ秒)
	KeepAliveInterval int

	Magic []byte
	// CTRL_*
	Ctrl int
	// サーバ情報
	ServerInfo Host
	// websocket のリクエストヘッダに付加する情報
	WsReqHeader http.Header
}

func (config TunnelParam) String() string {
	return fmt.Sprintf("TunnelConfig(mode=%s, server=%s)", config.Mode, config.ServerInfo.String())
}

// セッションの再接続時に、
// 再送信するためのデータを保持しておくパケット数
const PACKET_NUM_BASE = 30
const PACKET_NUM_DIV = 2
const PACKET_NUM = (PACKET_NUM_DIV * PACKET_NUM_BASE)

// 書き込みを結合する最大サイズ
const MAX_PACKET_SIZE = 10 * 1024

const TUNNEL_STREAM_ID_CTRL = 0
const TUNNEL_STREAM_ID_USR = 1

const CTRL_REQ_HEADER = 0
const CTRL_RESP_HEADER = 1

// PRE_ENC Can't be true until CryptCtrl after reconnection can use the same
const PRE_ENC = false

type DummyConn struct {
}

var dummyConn = &DummyConn{}

func (*DummyConn) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 0, fmt.Errorf("dummy read")
}
func (*DummyConn) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("dummy write")
}
func (*DummyConn) Close() error {
	return nil
}

type RingBuf struct {
	ring *ring.Ring
}

func NewRingBuf(num, bufsize int) *RingBuf {
	ring := ring.New(num)
	for index := 0; index < num; index++ {
		ring.Value = make([]byte, bufsize)
		ring = ring.Next()
	}
	return &RingBuf{ring}
}

func (ringBuf *RingBuf) getNext() []byte {
	buf := ringBuf.ring.Value.([]byte)
	ringBuf.ring = ringBuf.ring.Next()
	return buf
}

func (ringBuf *RingBuf) getCur() []byte {
	return ringBuf.ring.Value.([]byte)
}

type CtrlReqHeader struct {
	Host           Host
	TunnelStreamId uint32
}
type CtrlRespHeader struct {
	Success        bool
	Message        string
	TunnelStreamId uint32
}

type Ctrl struct {
	waitHeaderCount   chan int
	ctrlReqHeaderChan chan *CtrlReqHeader
}

type TunnelStream struct {
	conn      io.ReadWriteCloser
	Id        uint32
	bytesChan chan []byte //
	end       bool

	syncChan chan bool // channel for flow control

	// to hold packets resent to WritePackList, Keep packet buffers in the link.

	ringBufW  *RingBuf // Buffer for write.
	ringBufR  *RingBuf // Buffer for read.
	ReadNo    int64    // number of packets read in this session
	WriteNo   int64    // number of packets written in this session
	ReadSize  int64
	WriteSize int64

	ctrlRespHeaderChan chan *CtrlRespHeader

	ReadState  int
	WriteState int

	waitTimeInfo WaitTimeInfo
}

func (ts *TunnelStream) String() string {
	return fmt.Sprintf("TunnelStream(id: %d, syncChan len: %d, rxSeq: %d, tx: %d)",
		ts.Id, len(ts.syncChan), ts.ReadNo, ts.WriteNo)
}

const Session_state_authchallenge = "authchallenge"
const Session_state_authresponse = "authresponse"
const Session_state_authresult = "authresult"
const Session_state_authmiss = "authmiss"
const Session_state_header = "ctrlReqHeaderChan"
const Session_state_respheader = "respheader"
const Session_state_connected = "connected"
const Session_state_reconnecting = "reconnecting"
const Session_state_disconnected = "disconnected"

type WaitTimeInfo struct {
	stream2Tunnel time.Duration
	tunnel2Stream time.Duration
	packetReader  time.Duration
}

type Session struct {
	Id    int
	Token string

	// Channel for Packet writing
	packetChan    chan Packet
	packetEncChan chan Packet

	readSize  int64 // Size read from pipe
	wroteSize int64 // Size written in pipe

	tunnelStreamMap    map[uint32]*TunnelStream
	nextTunnelStreamId uint32

	ReadNo  int64 // Number of packets READ in this session
	WriteNo int64 // Number of packets made in this session

	// List of sending SessionPacket, maintains SessionPacket for the latest Packet_num.
	WritePackList *list.List

	RewriteNo int64 // The packet number to be resent, In the case of -1, there is packetNumber re -sending.

	ctrl Ctrl

	state string

	isTunnelServer bool

	ringBufEnc  *RingBuf
	encSyncChan chan bool

	packetWriterWaitTime time.Duration

	readState  int
	writeState int

	// Waiting for reconnect.
	// 0: No waiting, 1: Wait with either Read or Write, 2: Read/Write
	reconnetWaitState int

	releaseChan chan bool

	// member access excretion of this structure MUTEX
	mutex *Lock
}

func (session *Session) GetPacketBuf(citiId uint32, packSize uint16) []byte {
	if citiId >= TUNNEL_STREAM_ID_USR {
		if citi := session.getTunnelStream(citiId); citi != nil {
			buf := citi.ringBufR.getCur()
			if len(buf) < int(packSize) {
				log.Fatal().Msgf("illegal packet size: %d", len(buf))
			}
			return buf[:packSize]
		}
	}
	return make([]byte, packSize)
}

func (session *Session) SetState(state string) {
	session.state = state
}

func (session *Session) Setup() {
	for count := uint32(0); count < TUNNEL_STREAM_ID_USR; count++ {
		session.tunnelStreamMap[count] = NewTunnelStream(nil, count)
	}

	session.ctrl.waitHeaderCount = make(chan int, 100)
	session.ctrl.ctrlReqHeaderChan = make(chan *CtrlReqHeader, 1)
	//sessionInfo.ctrl.ctrlRespHeaderChan = make(chan *CtrlRespHeader,1)

	for count := 0; count < PACKET_NUM_DIV; count++ {
		session.encSyncChan <- true
	}
}

func newEmptySessionInfo(sessionId int, token string, isTunnelServer bool) *Session {
	sessionInfo := &Session{
		Id:                   sessionId,
		Token:                token,
		packetChan:           make(chan Packet, PACKET_NUM),
		packetEncChan:        make(chan Packet, PACKET_NUM),
		readSize:             0,
		wroteSize:            0,
		tunnelStreamMap:      map[uint32]*TunnelStream{},
		nextTunnelStreamId:   TUNNEL_STREAM_ID_USR,
		ReadNo:               0,
		WriteNo:              0,
		WritePackList:        new(list.List),
		RewriteNo:            -1,
		ctrl:                 Ctrl{},
		state:                "None",
		isTunnelServer:       isTunnelServer,
		ringBufEnc:           NewRingBuf(PACKET_NUM, BUFSIZE),
		encSyncChan:          make(chan bool, PACKET_NUM_DIV),
		packetWriterWaitTime: 0,
		readState:            0,
		writeState:           0,
		reconnetWaitState:    0,
		releaseChan:          make(chan bool, 3),
		mutex:                &Lock{},
	}

	sessionInfo.Setup()
	return sessionInfo
}

func DumpSession(stream io.Writer) {
	fmt.Fprintf(stream, "before sessionMgr.mutex: %s\n", sessionMgr.mutex.owner)

	sessionMgr.mutex.get("DumpSession")
	defer sessionMgr.mutex.rel()

	fmt.Fprintf(stream, "------------\n")
	fmt.Fprintf(stream, "sessionMgr.mutex: %s\n", sessionMgr.mutex.owner)
	for _, sessionInfo := range sessionMgr.sessionsByToken {
		fmt.Fprintf(stream, "sessionId: %d\n", sessionInfo.Id)
		fmt.Fprintf(stream, "token: %s\n", sessionInfo.Token)
		fmt.Fprintf(stream, "state: %s\n", sessionInfo.state)
		fmt.Fprintf(stream, "mutex onwer: %s\n", sessionInfo.mutex.owner)
		fmt.Fprintf(
			stream, "WriteNo, ReadNo: %d %d\n",
			sessionInfo.WriteNo, sessionInfo.ReadNo)
		fmt.Fprintf(stream, "packetChan: %d\n", len(sessionInfo.packetChan))
		fmt.Fprintf(stream, "packetEncChan: %d\n", len(sessionInfo.packetEncChan))
		fmt.Fprintf(stream, "encSyncChan: %d\n", len(sessionInfo.encSyncChan))
		// fmt.Fprintf(stream, "releaseChan: %d\n", len(sessionInfo.releaseChan))
		fmt.Fprintf(
			stream, "writeSize, ReadSize: %d, %d\n",
			sessionInfo.wroteSize, sessionInfo.readSize)
		fmt.Fprintf(stream, "tunnelStreamMap: %d\n", len(sessionInfo.tunnelStreamMap))
		fmt.Fprintf(
			stream, "readState %d, writeState %d\n",
			sessionInfo.readState, sessionInfo.writeState)

		for _, citi := range sessionInfo.tunnelStreamMap {
			fmt.Fprintf(stream, "======\n")
			fmt.Fprintf(stream, "Id: %d-%d\n", sessionInfo.Id, citi.Id)
			fmt.Fprintf(
				stream, "readState %d, writeState %d\n",
				citi.ReadState, citi.WriteState)
			fmt.Fprintf(
				stream, "syncChan: %d, bytesChan %d, readNo %d, writeNo %d\n",
				len(citi.syncChan), len(citi.bytesChan), citi.ReadNo, citi.WriteNo)
		}

		fmt.Fprintf(stream, "------------\n")
	}
}

var nextSessionId = 0

func NewSessionInfo(isTunnelServer bool) *Session {
	sessionMgr.mutex.get("NewSessionInfo")
	defer sessionMgr.mutex.rel()

	nextSessionId++

	randbin := make([]byte, 9)
	if _, err := io.ReadFull(rand.Reader, randbin); err != nil {
		panic(err.Error())
	}
	token := base64.StdEncoding.EncodeToString(randbin)
	sessionInfo := newEmptySessionInfo(nextSessionId, token, isTunnelServer)
	sessionMgr.sessionsByToken[sessionInfo.Token] = sessionInfo

	return sessionInfo
}

func (session *Session) UpdateSessionId(sessionId int, token string) {
	sessionMgr.mutex.get("UpdateSessionId")
	defer sessionMgr.mutex.rel()

	session.Id = sessionId
	session.Token = token
	sessionMgr.sessionsByToken[session.Token] = session
}

func NewTunnelStream(conn io.ReadWriteCloser, citiId uint32) *TunnelStream {
	tunnelStream := &TunnelStream{
		conn:               conn,
		Id:                 citiId,
		bytesChan:          make(chan []byte, PACKET_NUM),
		end:                false,
		syncChan:           make(chan bool, PACKET_NUM_DIV),
		ringBufW:           NewRingBuf(PACKET_NUM, BUFSIZE),
		ringBufR:           NewRingBuf(PACKET_NUM, BUFSIZE),
		ReadNo:             0,
		WriteNo:            0,
		ReadSize:           0,
		WriteSize:          0,
		ctrlRespHeaderChan: make(chan *CtrlRespHeader),
		ReadState:          0,
		WriteState:         0,
		waitTimeInfo:       WaitTimeInfo{},
	}
	for count := 0; count < PACKET_NUM_DIV; count++ {
		tunnelStream.syncChan <- true
	}
	return tunnelStream
}

func (session *Session) getCtrlReqHeader() *CtrlReqHeader {
	ctrl := session.ctrl

	ctrl.waitHeaderCount <- 0
	header := <-ctrl.ctrlReqHeaderChan
	<-ctrl.waitHeaderCount

	return header
}

func (session *Session) addTunnelStream(role string, conn io.ReadWriteCloser, tunnelStreamId uint32) *TunnelStream {
	sessionMgr.mutex.get("addTunnelStream")
	defer sessionMgr.mutex.rel()

	if tunnelStreamId == TUNNEL_STREAM_ID_CTRL {
		tunnelStreamId = session.nextTunnelStreamId
		session.nextTunnelStreamId++
		if session.nextTunnelStreamId <= TUNNEL_STREAM_ID_USR {
			log.Fatal().Str("role", role).Msg("tunnelStream id overflows")
		}
	}

	tunnelStream, exists := session.tunnelStreamMap[tunnelStreamId]
	if exists {
		log.Info().Str("role", role).Int("sessionId", session.Id).Msgf("tsId %d exists", tunnelStreamId)
		return tunnelStream
	}

	tunnelStream = NewTunnelStream(conn, tunnelStreamId)
	session.tunnelStreamMap[tunnelStreamId] = tunnelStream
	log.Info().Str("role", role).Int("sessionId", session.Id).Msgf("tunnelStream added, tunnelStreamId: %d, tunnelStream total: %d", tunnelStreamId, len(session.tunnelStreamMap))
	if len(session.tunnelStreamMap) > 0 {
		for tsId, ts := range session.tunnelStreamMap {
			log.Debug().Msgf("%d => %s", tsId, ts.String())
		}
	}
	return tunnelStream
}

func (session *Session) getTunnelStream(tunnelStreamId uint32) *TunnelStream {
	sessionMgr.mutex.get("getTunnelStream")
	defer sessionMgr.mutex.rel()

	if tunnelStream, exists := session.tunnelStreamMap[tunnelStreamId]; exists {
		return tunnelStream
	}
	return nil
}

func (session *Session) delTunnelStream(tunnelStream *TunnelStream) {
	sessionMgr.mutex.get("delTunnelStream")
	defer sessionMgr.mutex.rel()

	delete(session.tunnelStreamMap, tunnelStream.Id)
	log.Info().Int("sessionId", session.Id).Uint32("tunnelStreamId", tunnelStream.Id).Msgf("tunnelStreamId deleted, left total: %d", len(session.tunnelStreamMap))

	log.Info().Int("sessionId", session.Id).Uint32("tunnelStreamId", tunnelStream.Id).Msgf("discard bytesChan, total: %d", len(tunnelStream.bytesChan))
	for len(tunnelStream.bytesChan) > 0 {
		<-tunnelStream.bytesChan
	}
}

func (session *Session) hasTunnelStream() bool {
	sessionMgr.mutex.get("hasTunnelStream")
	defer sessionMgr.mutex.rel()
	return len(session.tunnelStreamMap) > TUNNEL_STREAM_ID_USR
}

// Transport is connection information
type Transport struct {
	Conn        io.ReadWriteCloser // connection
	CryptCtrl   *CryptCtrl         // encrypted information
	Session     *Session           // session information
	WriteBuffer bytes.Buffer
}

// Transport の生成
//
// @param conn コネクション
// @param pass 暗号化パスワード
// @param count 暗号化回数
// @param sessionInfo セッション情報
// @return Transport
func CreateConnInfo(conn io.ReadWriteCloser, pass *string, count int, sessionInfo *Session, isTunnelServer bool) *Transport {
	if sessionInfo == nil {
		sessionInfo = newEmptySessionInfo(0, "", isTunnelServer)
	}
	return &Transport{conn, CreateCryptCtrl(pass, count), sessionInfo, bytes.Buffer{}}
}

// 再送信パケット番号の送信
//
// @param readNo 接続先の読み込み済みパケット No
func (session *Session) SetReWrite(readNo int64) {
	if session.WriteNo > readNo {
		// こちらが送信したパケット数よりも相手が受け取ったパケット数が少ない場合、
		// パケットを再送信する。
		session.RewriteNo = readNo
	} else if session.WriteNo == readNo {
		// こちらが送信したパケット数と、相手が受け取ったパケット数が一致する場合、
		// 再送信はなし。
		session.RewriteNo = -1
	} else {
		// こちらが送信したパケット数よりも相手が受け取ったパケット数が多い場合、
		// そんなことはありえないのでエラー
		log.Fatal().Msg("mismatch WriteNo")
	}
}

type SessionManager struct {
	sessionsByToken map[string]*Session
	transportMap    map[int]*Transport
	relayMap        map[int]*Relay
	//conn2alive        map[io.ReadWriteCloser]bool // A map to determine if sessions on the connection are enabled.

	mutex Lock // mutex when accessing values in the SessionManager
}

var sessionMgr = SessionManager{
	sessionsByToken: map[string]*Session{},
	transportMap:    map[int]*Transport{},
	relayMap:        map[int]*Relay{},
	//conn2alive:        map[io.ReadWriteCloser]bool{},
}

// 指定のコネクションをセッション管理に登録する
func SetSessionConn(connInfo *Transport) {
	sessionId := connInfo.Session.Id
	log.Printf("set session %d conn", sessionId)

	sessionMgr.mutex.get("SetSessionConn")
	defer sessionMgr.mutex.rel()

	sessionMgr.transportMap[connInfo.Session.Id] = connInfo
	//sessionMgr.conn2alive[transport.Conn] = true
}

// 指定のセッション token  に紐付けられた Session を取得する
func GetSessionInfo(token string) (*Session, bool) {
	sessionMgr.mutex.get("GetSessionInfo")
	defer sessionMgr.mutex.rel()

	sessionInfo, has := sessionMgr.sessionsByToken[token]
	return sessionInfo, has
}

// Relay controls information that relayMap communication between tunnel and connection destination
type Relay struct {
	rev int // Revision of transport. Counts up each time reconnection is established.

	// reconnect function
	//
	// @param sessionInfo session information
	// @return *Transport Connected connection.
	// - nil if unable to reconnect.
	// Retry reconnection in this function.
	// If this function returns nil, give up reconnection.
	reconnectFunc func(sessionInfo *Session) *Transport

	shouldEnd    bool       // true when this Tunnel connection should be terminated
	exitChan     chan bool  // Channel for waiting for the shouldEnd of relay processing
	isConnecting bool       // true while reconnecting
	transport    *Transport // Connection information isConnecting pipe
	// reconnected chan bool //

	isTunnelStreamServer bool // true if citi is server
}

func (relay *Relay) sendRelease() {
	if relay.isTunnelStreamServer {
		releaseChan := relay.transport.Session.releaseChan //
		if len(releaseChan) == 0 {
			releaseChan <- true
		}
	}
}

type Packet struct {
	kind           int8 // PACKET_KIND_*
	tunnelStreamId uint32
	bytes          []byte // write data
}

func (pkt *Packet) String() string {
	return fmt.Sprintf("Packet(kind: %s, tunnelStreamId: %d, bytes: %d)", getKindName(pkt.kind), pkt.tunnelStreamId, len(pkt.bytes))
}

// SessionPacket holds the data written in the session
type SessionPacket struct {
	packetNumber int64
	packet       Packet
}

// cache packet in case of rewrite
func (session *Session) cacheWritePacket(packet *Packet) {
	writePackList := session.WritePackList
	writePackList.PushBack(SessionPacket{packetNumber: session.WriteNo, packet: *packet})
	if writePackList.Len() > PACKET_NUM {
		writePackList.Remove(writePackList.Front())
	}
	if PRE_ENC {
		if (session.WriteNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 {
			session.encSyncChan <- true
		}
	}
	session.WriteNo++
	session.wroteSize += int64(len(packet.bytes))
}

// write data to connection, save the written data in WritePackList.
func (t *Transport) writeNormalPacket(streamWriter io.Writer, tunnelStreamId uint32, bytes []byte) error {
	return writeBytesAsNormalPacketWithBuffer(streamWriter, tunnelStreamId, bytes, t.CryptCtrl, nil) // TBD use &transport.WriteBuffer as the buffer
	// return writeBytesAsNormalPacket(streamWriter, tunnelStreamId, bytes, transport.CryptCtrl)
}

func (t *Transport) writeNormalDirectPacket(streamWriter io.Writer, tunnelStreamId uint32, bytes []byte) error {
	return writeBytesAsNormalPacket(streamWriter, tunnelStreamId, bytes, t.CryptCtrl)
}

func (t *Transport) writeDummyPacket(streamWriter io.Writer) error {
	if _, err := streamWriter.Write(DummyKindBuf); err != nil {
		return err
	}
	return nil
}

func (t *Transport) writeSyncPacket(writer io.Writer, tunnelStreamId uint32, buf []byte) error {
	kind := PACKET_KIND_SYNC
	var kindBuf []byte
	switch kind {
	case PACKET_KIND_SYNC:
		kindBuf = SyncKindBuf
	default:
		log.Fatal().Msgf("illegal kind: %d", kind)
	}

	var buffer bytes.Buffer
	buffer.Grow(PACKET_LEN_HEADER + len(buf))

	if _, err := buffer.Write(kindBuf); err != nil {
		return err
	}
	if err := binary.Write(&buffer, binary.BigEndian, tunnelStreamId); err != nil {
		return err
	}
	if _, err := buffer.Write(buf); err != nil {
		return err
	}

	_, err := buffer.WriteTo(writer)
	return err
}

// read normal packet from conn
func (t *Transport) readNormalPacketFromConn(work []byte) (*Packet, error) {
	//var packetItem *PacketItem
	//var err error

	// read infinitely until a normal packet, or error happens
	log.Info().Msgf("going into the loop of reading packets from conn ...")
	for {
		packetItem, err := readPacketFromConn(t.Conn, t.CryptCtrl, work, t.Session)
		if err != nil {
			log.Err(err).Msgf("read from conn failed")
			return nil, err
		}

		if packetItem.kind != PACKET_KIND_DUMMY {
			t.Session.ReadNo++
			log.Debug().Msgf("dummy packet read")
		}

		if packetItem.kind == PACKET_KIND_SYNC {
			log.Debug().Msgf("packetSeq: %d, get sync ", int64(binary.BigEndian.Uint64(packetItem.bytes)))

			// Update syncChan when the other party receives it and set it to proceed with transmission processing.
			if citi := t.Session.getTunnelStream(packetItem.tunnelStreamId); citi != nil {
				citi.syncChan <- true
				log.Debug().Msgf("cit %d found, sync is put into syncChan", citi)
			} else {
				log.Debug().Msgf("cit %d not found, discard sync packet", packetItem.tunnelStreamId)
			}
		}

		if packetItem.kind == PACKET_KIND_NORMAL {
			log.Info().Msgf("normal packet read")
			//break
			t.Session.readSize += int64(len(packetItem.bytes))
			return packetItem, nil
		}
	}
	//transport.Session.readSize += int64(len(packetItem.bytes))
	//return packetItem, nil
}

// 再接続を行なう
//
// @param rev 現在のリビジョン
// @return Transport 再接続後のコネクション
// @return int 再接続後のリビジョン
// @return bool セッションを終了するかどうか。終了する場合 true
func (relay *Relay) reconnect(txt string, rev int) (*Transport, int, bool) {
	workRev, workConnInfo := relay.getRevAndTransport()
	sessionInfo := relay.transport.Session

	sessionInfo.mutex.get("reconnect")
	sessionInfo.reconnetWaitState++
	sessionInfo.mutex.rel()

	log.Printf("reconnect -- rev: %s, %d %d, %p", txt, rev, workRev, workConnInfo)

	reqConnect := false

	sub := func() bool {
		sessionInfo.mutex.get("reconnect-sub")
		defer sessionInfo.mutex.rel()

		if relay.rev != rev {
			if !relay.isConnecting {
				sessionInfo.reconnetWaitState--
				workRev = relay.rev
				workConnInfo = relay.transport
				return true
			}
		} else {
			relay.isConnecting = true
			relay.rev++
			reqConnect = true
			return true
		}
		return false
	}

	if relay.reconnectFunc != nil {
		for {
			if sub() {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}
	} else {
		reqConnect = true
		relay.rev++
	}

	if reqConnect {
		releaseSessionTransport(relay)
		reverseTunnelPreCloseHook(relay)

		if len(sessionInfo.packetChan) == 0 {
			// sessionInfo.packetChan 待ちで packetWriter が止まらないように
			// dummy を投げる。
			sessionInfo.packetChan <- Packet{kind: PACKET_KIND_DUMMY, tunnelStreamId: TUNNEL_STREAM_ID_CTRL}
		}

		if !relay.shouldEnd {
			sessionInfo.SetState(Session_state_reconnecting)

			workRev = relay.rev
			workInfo := relay.reconnectFunc(sessionInfo)
			if workInfo != nil {
				relay.transport = workInfo
				log.Printf("new transport -- %p", workInfo)
				sessionInfo.SetState(Session_state_connected)
			} else {
				relay.shouldEnd = true
				relay.transport = CreateConnInfo(dummyConn, nil, 0, sessionInfo, sessionInfo.isTunnelServer)
				log.Printf("set dummyConn")
			}
			workConnInfo = relay.transport

			func() {
				sessionInfo.mutex.get("reconnectFunc-shouldEnd")
				defer sessionInfo.mutex.rel()
				sessionInfo.reconnetWaitState--
			}()

			relay.isConnecting = false
		}
	}

	log.Printf(
		"connected: [%s] rev -- %d, shouldEnd -- %v, %p",
		txt, workRev, relay.shouldEnd, workConnInfo)
	return workConnInfo, workRev, relay.shouldEnd
}

func releaseSessionTransport(relay *Relay) {
	transport := relay.transport
	log.Debug().Int("sessionId", transport.Session.Id).Msgf("release transport")

	sessionMgr.mutex.get("releaseSessionTransport")
	defer sessionMgr.mutex.rel()

	//delete(sessionMgr.conn2alive, transport.Conn)
	delete(sessionMgr.transportMap, transport.Session.Id)

	_ = transport.Conn.Close()
	relay.sendRelease()
}

func getSessionTransport(session *Session) *Transport {
	sessionId := session.Id
	log.Print("getSessionTransport ... session: ", sessionId)

	sub := func() *Transport {
		sessionMgr.mutex.get("getSessionTransport-sub")
		defer sessionMgr.mutex.rel()

		if connInfo, has := sessionMgr.transportMap[sessionId]; has {
			return connInfo
		}
		return nil
	}
	for {
		if connInfo := sub(); connInfo != nil {
			log.Print("getSessionTransport ok ... session: ", sessionId)
			return connInfo
		}
		// if !session.hasTunnelStream() {
		//     log.Print( "getSessionTransport ng ... session: ", sessionId )
		//     return nil
		// }

		time.Sleep(500 * time.Millisecond)
	}
}

// 指定のセッションに対応するコネクションを取得する
func WaitPauseSession(sessionInfo *Session) bool {
	log.Print("WaitPauseSession start ... session: ", sessionInfo.Id)
	sub := func() bool {
		sessionMgr.mutex.get("WaitPauseSession-sub")
		defer sessionMgr.mutex.rel()

		return sessionInfo.reconnetWaitState == 2
	}
	for {
		if sub() {
			log.Print("WaitPauseSession ok ... session: ", sessionInfo.Id)
			return true
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// get connection information
//
// @return int revision information
// @return *Transport connection information
func (relay *Relay) getRevAndTransport() (int, *Transport) {
	// TODO necessary?
	session := relay.transport.Session
	session.mutex.get("getRevAndTransport")
	defer session.mutex.rel()

	return relay.rev, relay.transport
}

// tunnel stream (bytesChan) => conn
func tunnel2Stream(sessionInfo *Session, tunnelStream *TunnelStream, exitChan chan<- bool) {
	for {
		tunnelStream.ReadState = 10

		timeStart := time.Now()
		readBuf := <-tunnelStream.bytesChan
		tunnelStream.ReadState = 20

		waitingTime := time.Now().Sub(timeStart)
		tunnelStream.waitTimeInfo.tunnel2Stream += waitingTime
		if waitingTime > 5*time.Millisecond {
			log.Debug().Msgf("wait bytes channel, readNo: %d, cost: %s", tunnelStream.ReadNo, waitingTime)
		}
		readSize := len(readBuf)
		log.Debug().Msgf("read from bytes channel, readNo: %d, size: %d", tunnelStream.ReadNo, readSize)

		if (tunnelStream.ReadNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 { // send SYNC after reading a certain number
			var buffer bytes.Buffer
			_ = binary.Write(&buffer, binary.BigEndian, tunnelStream.ReadNo)
			tunnelStream.ReadState = 30

			sessionInfo.packetChan <- Packet{bytes: buffer.Bytes(), kind: PACKET_KIND_SYNC, tunnelStreamId: tunnelStream.Id} // push sync packet
			log.Info().Msg("sync sent to packet chan")
		}
		tunnelStream.ReadNo++
		tunnelStream.ReadSize += int64(len(readBuf))

		if readSize == 0 {
			log.Warn().Msgf("read 0-size from bytes channel, exit")
			break
		}
		tunnelStream.ReadState = 40

		_, writeErr := tunnelStream.conn.Write(readBuf)
		tunnelStream.ReadState = 50

		if writeErr != nil {
			log.Err(writeErr).Msgf("conn writing failed, readNo: %d, exit", tunnelStream.ReadNo)
			break
		}
	}

	sessionInfo.delTunnelStream(tunnelStream) // Remove data from tunnelStream.bytesChan to prevent stuffing
	exitChan <- true
}

// resend data to Tunnel
//
// @param info pipe info
// @param transport connection information
// @param rev revision
// @return bool true to continue processing
func rewrite2Tunnel(relay *Relay, connInfoRev *ConnInfoRev) bool {
	// resend packets after reconnection
	session := connInfoRev.transport.Session
	if session.RewriteNo == -1 {
		return true
	}

	log.Info().Int("sessionId", session.Id).Msgf("rewrite after reconnection, writeNo: %d, rewriteNo: %d", session.WriteNo, session.RewriteNo)

	for session.WriteNo > session.RewriteNo {
		item := session.WritePackList.Front()
		if item == nil {
			log.Fatal().Msgf("packet not found, RewriteNo: %d", session.RewriteNo)
		}

		for ; item != nil; item = item.Next() {
			sessionPacket := item.Value.(SessionPacket)

			if sessionPacket.packetNumber == session.RewriteNo { // found a sessionPacket to resend
				var err error

				streamContinues := true
				streamContinues, err = writePacketToWriter(&sessionPacket.packet, connInfoRev.transport.Conn, connInfoRev.transport, false)
				if !streamContinues {
					return false
				}
				if err != nil {
					end := false
					_ = connInfoRev.transport.Conn.Close()
					connInfoRev.transport, connInfoRev.rev, end = relay.reconnect("rewrite", connInfoRev.rev)
					if end {
						return false
					}
				} else {
					log.Printf("rewrite: %d, %d, %p", session.RewriteNo, sessionPacket.packet.kind, sessionPacket.packet.bytes)
					if session.WriteNo == session.RewriteNo {
						session.RewriteNo = -1
					} else {
						session.RewriteNo++
					}
				}
				break
			}
		}

	}
	return true
}

// conn => tunnel stream (packetChan)
func stream2Tunnel(tunnelStream *TunnelStream, pipeInfo *Relay, exitChan chan<- bool) {
	_, connInfo := pipeInfo.getRevAndTransport()
	sessionInfo := connInfo.Session
	sessionId := sessionInfo.Id
	packetChan := sessionInfo.packetChan

	end := false
	for !end {
		tunnelStream.WriteState = 10
		if (tunnelStream.WriteNo % PACKET_NUM_BASE) == 0 {
			// In order to leave a buffer for retransmission when reconnecting after tunnel disconnection, get syncChan for every PACKET_NUM_BASE
			// Don't send too much when the other party hasn't received it.
			syncWaitingTimeStart := time.Now()
			<-tunnelStream.syncChan // TODO wait for sync signal, how is it triggered?
			waitingTime := time.Now().Sub(syncWaitingTimeStart)
			tunnelStream.waitTimeInfo.stream2Tunnel += waitingTime
			if waitingTime >= 5*time.Millisecond {
				log.Debug().Int("sessionId", sessionId).Msgf("conn => tunnel stream, waitingTime: %s, total waitingTime: %s, tunnelStream writeNo: %d",
					waitingTime, tunnelStream.waitTimeInfo.stream2Tunnel, tunnelStream.WriteNo)
			}
			log.Debug().Int("sessionId", sessionId).Msgf("get sync packet")
		}
		tunnelStream.WriteNo++
		tunnelStream.WriteState = 20

		buf := tunnelStream.ringBufW.getNext() // switch buffer
		readSize, readErr := tunnelStream.conn.Read(buf)
		tunnelStream.WriteState = 30

		log.Debug().Int("sessionId", sessionId).Msgf("conn => tunnel stream, WriteNo: %d, readSize: %d", tunnelStream.WriteNo, readSize)
		if readErr != nil {
			log.Err(readErr).Int("sessionId", sessionId).Msgf("conn bytes reading err, writeNo: %d", sessionInfo.WriteNo)
			packetChan <- Packet{bytes: make([]byte, 0), kind: PACKET_KIND_NORMAL, tunnelStreamId: tunnelStream.Id} // write 0 bytes data to the destination when the input source is dead
			break
		}
		if readSize == 0 {
			log.Warn().Int("sessionId", sessionInfo.Id).Msg("ignore 0-size packet")
			continue
		}
		tunnelStream.WriteSize += int64(readSize)
		tunnelStream.WriteState = 40

		if (tunnelStream.WriteNo%PACKET_NUM_BASE) == 0 && len(tunnelStream.syncChan) == 0 {
			work := <-tunnelStream.syncChan // if it's the last packet in the packet group and packetNumber SYNC is coming, wait for SYNC before sending
			tunnelStream.syncChan <- work   // Since we read ahead SYNC, we write back SYNC.
		}
		tunnelStream.WriteState = 50

		packetChan <- Packet{bytes: buf[:readSize], kind: PACKET_KIND_NORMAL, tunnelStreamId: tunnelStream.Id}
	}

	exitChan <- true
}

type ConnInfoRev struct {
	transport *Transport
	rev       int
}

// parses control packet from binary
func handleControlPacket(sessionInfo *Session, buf []byte) {
	if len(buf) == 0 {
		log.Print("ignore empty buffer 0")
		return
	}
	kind := buf[0]
	body := buf[1:]
	var buffer bytes.Buffer
	buffer.Write(body)

	switch kind {
	case CTRL_REQ_HEADER:
		header := CtrlReqHeader{}
		if err := json.NewDecoder(&buffer).Decode(&header); err != nil {
			log.Fatal().Err(err).Msgf("fail to parse ctrlReqHeaderChan")
		}
		sessionInfo.ctrl.ctrlReqHeaderChan <- &header // bytes from conn, now this control request header is pushed into chan
		log.Info().Msgf("TunnelStream ctrl_req_header pushed ctrlReqHeaderChan")
	case CTRL_RESP_HEADER:
		resp := CtrlRespHeader{}
		if err := json.NewDecoder(&buffer).Decode(&resp); err != nil {
			log.Fatal().Msgf("failed to read ctrlReqHeaderChan: %v", err)
		}
		if citi := sessionInfo.getTunnelStream(resp.TunnelStreamId); citi != nil {
			citi.ctrlRespHeaderChan <- &resp
			log.Info().Msgf("ctrl_resp_header pushed to TunnelStream %d", citi.Id)
		} else {
			log.Error().Msgf("TunnelStream %d not found, ctrl_resp_header is discarded", resp.TunnelStreamId)
		}
	}
}

// read from conn and parsed into packet
func packetReader(relay *Relay) {
	rev, connInfo := relay.getRevAndTransport()
	session := connInfo.Session

	log.Info().Msgf("conn reader goroutine starts ...")
	buf := make([]byte, BUFSIZE)
	for {
		readSize := 0
		var tunnelStream *TunnelStream
		for {
			session.readState = 10
			if packet, err := connInfo.readNormalPacketFromConn(buf); err != nil {
				session.readState = 20
				log.Err(err).Msgf("fail to read from conn, readNo: %d", session.ReadNo)

				end := false
				_ = connInfo.Conn.Close()
				connInfo, rev, end = relay.reconnect("read", rev)
				if end {
					readSize = 0
					relay.shouldEnd = true
					break
				}
			} else {
				session.readState = 30
				log.Debug().Msgf("read from conn, size: %d", len(packet.bytes))

				if packet.tunnelStreamId == TUNNEL_STREAM_ID_CTRL {
					log.Debug().Msgf("TunnelStream control packet")
					handleControlPacket(session, packet.bytes)
					readSize = 1 // set readSize to 1 so that the process doesn't shouldEnd
				} else {
					if tunnelStream = session.getTunnelStream(packet.tunnelStreamId); tunnelStream != nil {
						// packet.bytes to tunnelStream.bytesChan
						// put in and processed in another thread.
						// On the other hand, packet.bytes refers to a fixed address, so if you readNormalPacketFromConn before processing in another thread, the contents of packet.bytes will be overwritten.
						// Copy to prevent that.

						// cloneBuf := tunnelStream.ringBufR.getNext()[:len(packet.bytes)]
						// copy( cloneBuf, packet.bytes )
						// tunnelStream.ringBufR.getNext() // TODO comment out this?

						cloneBuf := packet.bytes
						waitingTimeStart := time.Now()
						tunnelStream.bytesChan <- cloneBuf // TODO buffer is sent over channel, need to copy?
						waitingTime := time.Now().Sub(waitingTimeStart)
						tunnelStream.waitTimeInfo.packetReader += waitingTime
						if waitingTime >= 5*time.Millisecond {
							log.Debug().Msgf("get buffer from bytes channel, readNo: %d, cost: %s", tunnelStream.ReadNo, waitingTime)
						}
						readSize = len(cloneBuf)
					} else {
						log.Info().Msgf("cit not found: %d, discard the packet", packet.tunnelStreamId)
						readSize = 1
					}
				}
				if readSize == 0 {
					if packet.tunnelStreamId == TUNNEL_STREAM_ID_CTRL {
						relay.shouldEnd = true
					}
				}
				break
			}
		}
		session.readState = 40

		if readSize == 0 {
			if tunnelStream != nil && len(tunnelStream.syncChan) == 0 {
				tunnelStream.syncChan <- true // when exiting, stream2Tunnel() may be waiting, notify syncChan here
			}
			session.readState = 50

			if relay.shouldEnd { // stream ends or read 0-size buffer
				relay.sendRelease()
				for _, workCiti := range session.tunnelStreamMap { // shouldEnd all tunnel streams
					if len(workCiti.syncChan) == 0 {
						workCiti.syncChan <- true // when exiting, stream2Tunnel() may be waiting, notify syncChan here
					}
				}
				break
			}
		}
	}

	reverseTunnelPreCloseHook(relay)
	log.Info().Int("sessionId", session.Id).Msgf("conn reader exits")
	relay.exitChan <- true
}

func reconnectAndRewrite(info *Relay, connInfoRev *ConnInfoRev) bool {
	end := false
	connInfoRev.transport, connInfoRev.rev, end = info.reconnect("write", connInfoRev.rev)
	if end {
		return false
	}
	if !rewrite2Tunnel(info, connInfoRev) {
		return false
	}
	return true
}

func packetEncrypter(info *Relay) {
	packChan := info.transport.Session.packetChan

	ringBufEnc := info.transport.Session.ringBufEnc
	encSyncChan := info.transport.Session.encSyncChan

	encNo := uint64(0)
	for {
		packet := <-packChan

		switch packet.kind {
		case PACKET_KIND_NORMAL:
			if (encNo % PACKET_NUM_BASE) == 0 {
				<-encSyncChan
			}
			encNo++
		}

		switch packet.kind {
		case PACKET_KIND_NORMAL:
			buf := ringBufEnc.getNext()
			//bytes := make([]byte,BUFSIZE)

			if info.transport.CryptCtrl != nil {
				packet.bytes = info.transport.CryptCtrl.enc.Process(
					packet.bytes, buf)
			}
		}

		info.transport.Session.packetEncChan <- packet
	}
}

// write packets to conn, stream ends when boolean returning value is set
// writer could be a transport writer or a buffer writer
func writePacketToWriter(pkt *Packet, writer io.Writer, transport *Transport, needToCache bool) (bool, error) {
	var writeErr error
	sessionId := transport.Session.Id

	switch pkt.kind {
	case PACKET_KIND_EOS:
		log.Debug().Int("sessionId", sessionId).Msgf("eos")
		return false, nil
	case PACKET_KIND_SYNC:
		writeErr = transport.writeSyncPacket(writer, pkt.tunnelStreamId, pkt.bytes)
		log.Debug().Int("sessionId", sessionId).Msgf("sync sent")
	case PACKET_KIND_NORMAL:
		writeErr = transport.writeNormalPacket(writer, pkt.tunnelStreamId, pkt.bytes)
	case PACKET_KIND_NORMAL_DIRECT:
		writeErr = transport.writeNormalDirectPacket(writer, pkt.tunnelStreamId, pkt.bytes)
	case PACKET_KIND_DUMMY:
		writeErr = transport.writeDummyPacket(writer)
		needToCache = false
	default:
		log.Fatal().Msgf("illegal kind: %d", pkt.kind)
	}

	if needToCache && writeErr == nil {
		transport.Session.cacheWritePacket(pkt)
	}
	return true, writeErr
}

// packetChan => conn
func packetWriter(role string, relay *Relay) {
	session := relay.transport.Session
	sessionId := session.Id
	packetChan := session.packetChan
	if PRE_ENC {
		packetChan = session.packetEncChan
	}

	var connInfoRev ConnInfoRev
	connInfoRev.rev, connInfoRev.transport = relay.getRevAndTransport()

	var buffer bytes.Buffer

collectAndWriteLoop:
	for {
		session.writeState = 10

		packetChanWaitingTimeStart := time.Now()
		packet := <-packetChan
		span := time.Now().Sub(packetChanWaitingTimeStart)
		if span > 500*time.Microsecond {
			session.packetWriterWaitTime += span
			if span > 5*time.Millisecond {
				log.Debug().Str("role", role).Int("sessionId", sessionId).Msgf("get a packet from packetChan(%v), waited for %s", packetChan, span)
			}
		}

		session.writeState = 20
		buffer.Reset()
		// TODO buffer the first packet into `buffer`, so we can remove the last one-packet writing call

		for len(packetChan) > 0 && packet.kind == PACKET_KIND_NORMAL { // there are more NORMAL packet, note if not going into the loop, pkt.bytes are not buffered
			// packets are buffered, sent in batch
			if buffer.Len()+len(packet.bytes) > MAX_PACKET_SIZE {
				break // cannot hold more, have to send now
			}

			sentPkt := Packet{bytes: packet.bytes, kind: PACKET_KIND_NORMAL_DIRECT, tunnelStreamId: packet.tunnelStreamId}
			streamContinues, err := writePacketToWriter(&sentPkt, &buffer, connInfoRev.transport, true) // bytes written to buffer
			if err != nil {
				log.Fatal().Str("role", role).Int("sessionId", sessionId).Err(err).Msgf("fail to write to conn")
			}
			if !streamContinues {
				break collectAndWriteLoop
			}

			packet = <-packetChan // read more
		}

		session.writeState = 30
		if buffer.Len() != 0 {
			log.Debug().Int("sessionId", sessionId).Msgf("write buffered packets, size: %d ...", buffer.Len())
			if _, err := connInfoRev.transport.Conn.Write(buffer.Bytes()); err != nil { // use transport to write bytes
				log.Err(err).Str("role", role).Int("sessionId", sessionId).Msgf("tunnel batch writing failed, writeNo: %d", connInfoRev.transport.Session.WriteNo)

				// Batch buffer is encrypted with the cipher before reconnect, so if sent as is, decryption fails on the receiving side.
				// To avoid that, if batch write fails, recover with rewrite without batch writing.
				if !reconnectAndRewrite(relay, &connInfoRev) {
					break
				}
			}
		}

		session.writeState = 40
		// in case packet is not buffer into `buffer`
		// TODO try to remove this call
		if !writePacketToTransportWithRetry(relay, &packet, &connInfoRev) { // write one packet
			break
		}
	}
	log.Info().Str("role", role).Int("sessionId", sessionId).Msg("writing to conn ends")

	relay.exitChan <- true
}

// Write packet to connInfoRev.
//
// If writing fails, reconnect and resend.
// When resending, resolve the inconsistency with its ReadNo of the sending party, also resend data that has already been sent.
// When resending data that has already been sent, resend the data up to just before writeNo.
// Send data after writeNo using packet data.
// returns whether continues
func writePacketToTransportWithRetry(relay *Relay, pkt *Packet, connInfoRev *ConnInfoRev) bool {
	session := connInfoRev.transport.Session
	for {
		log.Debug().Int("sessionId", session.Id).Msgf("to write bytes to conn, WriteNo: %d, pkt: %s", session.WriteNo, pkt.String())
		streamContinues, err := writePacketToWriter(pkt, connInfoRev.transport.Conn, connInfoRev.transport, true)
		if err == nil {
			log.Debug().Int("sessionId", session.Id).Msgf("pkt written, streamContinues: %t", streamContinues)
			return streamContinues
		}

		log.Err(err).Msgf("failed to write pkt to transport, writeNo: %d", session.WriteNo)
		if !reconnectAndRewrite(relay, connInfoRev) {
			log.Error().Int("sessionId", session.Id).Msgf("retry failed, writeNo: %d", session.WriteNo)
			return false
		}
		log.Debug().Int("sessionId", session.Id).Msgf("retry to write, writeNo: %d", session.WriteNo)
	}
}

func newPipeInfo(connInfo *Transport, citServerFlag bool, reconnect func(sessionInfo *Session) *Transport) (*Relay, bool) {
	sessionMgr.mutex.get("newPipeInfo")
	defer sessionMgr.mutex.rel()

	sessionInfo := connInfo.Session
	info, has := sessionMgr.relayMap[sessionInfo.Id]
	if has {
		return info, false
	}

	info = &Relay{
		reconnectFunc: reconnect,
		transport:     connInfo,
		exitChan:      make(chan bool),
		// reconnected:   make(chan bool),
		isTunnelStreamServer: citServerFlag,
	}
	sessionMgr.relayMap[sessionInfo.Id] = info
	return info, true
}

func startRelaySession(role string, connInfo *Transport, interval int, citServerFlag bool, reconnect func(sessionInfo *Session) *Transport) *Relay {
	pipeInfo, isSessionNew := newPipeInfo(connInfo, citServerFlag, reconnect)
	connInfo.Session.SetState(Session_state_connected)
	sessionId := connInfo.Session.Id
	if !isSessionNew {
		log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("not a new session, skip process reconnect")
		return pipeInfo
	}

	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("launch reader/writer routines ...")
	go packetWriter(role, pipeInfo)
	go packetReader(pipeInfo)
	if PRE_ENC {
		go packetEncrypter(pipeInfo)
	}

	sessionInfo := connInfo.Session

	// keepalive goroutine
	go func() {
		log.Info().Str("role", role).Msgf("start keepalive routine ...")

		// TODO update this to a better way
		for !pipeInfo.shouldEnd {
			for sleepTime := 0; sleepTime < interval; sleepTime += KeepaliveSleepMs {
				time.Sleep(KeepaliveSleepMs * time.Millisecond)
				if pipeInfo.shouldEnd {
					break
				}
			}
			if !pipeInfo.isConnecting {
				sessionInfo.packetChan <- Packet{kind: PACKET_KIND_DUMMY, tunnelStreamId: TUNNEL_STREAM_ID_CTRL}
			}
		}
		log.Info().Int("sessionId", sessionId).Msgf("keepalive routine exits")
	}()

	return pipeInfo
}

// KeepaliveSleepMs interval for keepalive check
// If this is long, it takes time to wait for localRelay post-processing.
// If it's short, it will be heavy.
const KeepaliveSleepMs = 500

// Relay tunnel stream between transport stream
func localRelay(relay *Relay, tunnelStream *TunnelStream, hostInfo Host) {
	exitChan := make(chan bool)
	session := relay.transport.Session

	go stream2Tunnel(tunnelStream, relay, exitChan)   // TunnelStream packetChan <= conn
	go tunnel2Stream(session, tunnelStream, exitChan) // conn <= TunnelStream bytesChan

	<-exitChan
	_ = tunnelStream.conn.Close()

	<-exitChan

	log.Printf("close tunnelStream: sessionId %d, Id %d, read %d, write %d", session.Id, tunnelStream.Id, tunnelStream.ReadSize, tunnelStream.WriteSize)
	log.Printf("close tunnelStream: readNo %d, writeNo %d, bytesChan %d", tunnelStream.ReadNo, tunnelStream.WriteNo, len(tunnelStream.bytesChan))
	log.Printf("close tunnelStream: session readNo %d, session writeNo %d", session.ReadNo, session.WriteNo)
	log.Printf("waitTime: stream2Tunnel %s, tunnel2Stream %s, packetWriter %s, packetReader %s",
		tunnelStream.waitTimeInfo.stream2Tunnel, tunnelStream.waitTimeInfo.tunnel2Stream, session.packetWriterWaitTime, tunnelStream.waitTimeInfo.packetReader)
}

// 再接続情報
type ReconnectInfo struct {
	// 再接続後のコネクション情報
	Conn *Transport
	// エラー時、再接続の処理を継続するかどうか。継続する場合 true。
	Cont bool
	// 再接続でエラーした際のエラー
	Err error
}

// 再接続をリトライする関数を返す
func CreateToReconnectFunc(reconnect func(sessionInfo *Session) ReconnectInfo) func(sessionInfo *Session) *Transport {
	return func(sessionInfo *Session) *Transport {
		timeList := []time.Duration{
			500 * time.Millisecond,
			1000 * time.Millisecond,
			2000 * time.Millisecond,
			5000 * time.Millisecond,
		}
		index := 0
		sessionId := 0
		if sessionInfo != nil {
			sessionId = sessionInfo.Id
		}
		for {
			timeout := timeList[index]
			log.Printf(
				"reconnecting... session: %d, timeout: %v", sessionId, timeout)
			reconnectInfo := reconnect(sessionInfo)
			if reconnectInfo.Err == nil {
				log.Print("reconnect -- ok session: ", sessionId)
				return reconnectInfo.Conn
			}
			log.Printf("reconnecting error -- %s\n", reconnectInfo.Err)
			if !reconnectInfo.Cont {
				log.Print("reconnect -- ng session: ", sessionId)
				return nil
			}
			time.Sleep(timeout)
			if index < len(timeList)-1 {
				index++
			}
		}
	}
}

type NetListener struct {
	listener net.Listener
}

func (l *NetListener) Accept() (io.ReadWriteCloser, error) {
	return l.listener.Accept()
}
func (l *NetListener) Close() error {
	return l.listener.Close()
}

type Listener interface {
	Accept() (io.ReadWriteCloser, error)
	Close() error
}

type RelayListener struct {
	listener Listener
	forward  Forward
}

func (listener *RelayListener) Close() {
	_ = listener.listener.Close()
}

type ListenGroup struct {
	listeners []RelayListener
}

func (group *ListenGroup) Close() {
	for _, info := range group.listeners {
		info.Close()
	}
}

func NewListen(isClient bool, forwardList []Forward) (*ListenGroup, []Forward) {
	return NewListenWithMaker(isClient, forwardList, func(dst string) (Listener, error) {
		listen, err := net.Listen("tcp", dst)
		if err != nil {
			return nil, err
		}
		return &NetListener{listen}, nil
	})
}

func NewListenWithMaker(isClient bool, forwardList []Forward, listenMaker func(dst string) (Listener, error)) (*ListenGroup, []Forward) {
	listenGroup := ListenGroup{listeners: []RelayListener{}}
	var localForwards []Forward

	for _, forwardInfo := range forwardList {
		if (isClient && !forwardInfo.IsReverse) || (!isClient && forwardInfo.IsReverse) {
			local, err := listenMaker(forwardInfo.Src.String())
			if err != nil {
				log.Fatal().Err(err)
				return nil, []Forward{}
			}
			listenGroup.listeners = append(listenGroup.listeners, RelayListener{local, forwardInfo})
			log.Printf("add to listener listenGroup: %s", forwardInfo.String())
		} else {
			localForwards = append(localForwards, forwardInfo)
			log.Printf("add to local forwards: %s", forwardInfo.String())
		}
	}

	return &listenGroup, localForwards
}

func acceptAndRelayForever(role string, listener RelayListener, relay *Relay) {
	for {
		acceptAndRelay(role, listener, relay)
	}
}

func acceptAndRelay(role string, listener RelayListener, relay *Relay) {
	sessionId := relay.transport.Session.Id

	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("listening connections at %s ... (targeting %s)",
		listener.forward.Src.String(), listener.forward.Dest.String())
	conn, err := listener.listener.Accept()
	if err != nil {
		log.Fatal().Err(err)
	}
	needClose := true
	defer func() {
		if needClose {
			_ = conn.Close()
		}
	}()

	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("new connection accepted")

	tunnelStream := relay.transport.Session.addTunnelStream(role, conn, TUNNEL_STREAM_ID_CTRL)
	dest := listener.forward.Dest
	transport := relay.transport

	{
		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_REQ_HEADER})
		buf, _ := json.Marshal(&CtrlReqHeader{Host: dest, TunnelStreamId: tunnelStream.Id})
		buffer.Write(buf)
		transport.Session.packetChan <- Packet{bytes: buffer.Bytes(), kind: PACKET_KIND_NORMAL, tunnelStreamId: TUNNEL_STREAM_ID_CTRL} // accept a new connection, push ctrl_req_header to notify the other party
		log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("ctrl_req_header pushed to packetChan(%v), wait for responses ...", transport.Session.packetChan)
	}

	respHeader := <-tunnelStream.ctrlRespHeaderChan
	if respHeader.Success {
		log.Info().Msgf("ctrl_resp_header received, relay accepted connection")
		go localRelay(relay, tunnelStream, dest) // server side, accept and relay
		needClose = false
	} else {
		log.Error().Str("role", role).Int("sessionId", sessionId).Msgf("failed to connect %s:%s", dest.String(), respHeader.Message)
	}
}

// ListenAndNewConnect waits for a session to pass through Tunnel & connect to the communication destination of the session
// @param transport Tunnel
// @param port Listening port number
// @param parm tunnel information
// @param reconnect reconnection function
func ListenAndNewConnect(isClient bool, listenGroup *ListenGroup, localForwardList []Forward, connInfo *Transport, param *TunnelParam, reconnect func(sessionInfo *Session) *Transport) {
	ListenAndNewConnectWithDialer(isClient, listenGroup, localForwardList, connInfo, param, reconnect, func(dst string) (io.ReadWriteCloser, error) {
		log.Info().Msgf("dial %s", dst)
		return net.Dial("tcp", dst)
	})
}

func ListenAndNewConnectWithDialer(isClient bool, listenGroup *ListenGroup, localForwards []Forward, connInfo *Transport, param *TunnelParam, reconnect func(sessionInfo *Session) *Transport, dialer func(dst string) (io.ReadWriteCloser, error)) {
	role := "server"
	if isClient {
		role = "client"
	}

	relay := startRelaySession(role, connInfo, param.KeepAliveInterval, len(listenGroup.listeners) > 0, reconnect)

	for _, listener := range listenGroup.listeners {
		go acceptAndRelayForever(role, listener, relay) // start each listening in the listenerGroup
	}

	log.Debug().Str("role", role).Msgf("start local forwards ...")
	if len(localForwards) > 0 {
		for {
			ctrlReqHeader := connInfo.Session.getCtrlReqHeader()
			if ctrlReqHeader == nil {
				log.Info().Msgf("receive nil ctrlReqHeader, exit the local forwarding loop")
				break
			}
			log.Debug().Msgf("get non-nil ctrlReqHeader, initiate a new connection now ...")
			go establishNewConnection(role, dialer, ctrlReqHeader, relay)
		}
		log.Debug().Str("role", role).Msgf("local forwards ended")
	}

	log.Debug().Str("role", role).Msgf("waiting listener group exiting ...")
	if len(listenGroup.listeners) > 0 {
		for {
			log.Debug().Str("role", role).Msgf("wait for releaseChan")
			if !<-connInfo.Session.releaseChan {
				break
			}
			log.Debug().Str("role", role).Msgf("client side: %t", isClient)
			if !isClient {
				break
			}
		}
		log.Debug().Str("role", role).Msgf("local listeners ended")
	}
	log.Debug().Str("role", role).Msgf("disconnected")
	connInfo.Session.SetState(Session_state_disconnected)
}

// establishNewConnection initiate a new tcp connection
func establishNewConnection(role string, dialer func(dst string) (io.ReadWriteCloser, error), header *CtrlReqHeader, relay *Relay) {
	destAddr := header.Host.String()
	destConn, err := dialer(destAddr)

	sessionInfo := relay.transport.Session
	sessionId := sessionInfo.Id
	tunnelStream := sessionInfo.addTunnelStream(role, destConn, header.TunnelStreamId)

	{ // push ctrl_resp_header
		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_RESP_HEADER})
		resp := CtrlRespHeader{err == nil, fmt.Sprint(err), header.TunnelStreamId}
		buf, _ := json.Marshal(&resp)
		buffer.Write(buf)
		sessionInfo.packetChan <- Packet{bytes: buffer.Bytes(), kind: PACKET_KIND_NORMAL, tunnelStreamId: TUNNEL_STREAM_ID_CTRL} // ctrl_resp_header pushed
		log.Info().Str("role", role).Int("sessionId", sessionId).Msg("ctrl resp ctrlReqHeaderChan pushed into packetChan")

		if err != nil { // note this is the dialing error
			log.Err(err).Str("role", role).Int("sessionId", sessionId).Msgf("fail to dial %s", destAddr)
			return
		}
	}
	defer func() { _ = destConn.Close() }()

	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("connected to %s, star relaying ...", destAddr)
	localRelay(relay, tunnelStream, header.Host) // client side, connect and relay

	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("connection to %s closed", destAddr)
}

// sends a dummy(nil) ctrlReqHeaderChan to avoid waiting
func reverseTunnelPreCloseHook(info *Relay) {
	sessionInfo := info.transport.Session

	log.Info().Msgf("sessionId: %d, pre close action, is reverse tunnel: %t", sessionInfo.Id, sessionInfo.isTunnelServer)
	if sessionInfo.isTunnelServer {
		for len(sessionInfo.ctrl.waitHeaderCount) > 0 {
			count := len(sessionInfo.ctrl.waitHeaderCount)
			for index := 0; index < count; index++ {
				sessionInfo.ctrl.ctrlReqHeaderChan <- nil // send a dummy to avoid waiting for connection
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
