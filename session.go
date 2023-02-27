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

const CTRL_REQ_NEW_CONNECTION = 0
const CTRL_RESP_CONNECTION_ESTABLISHED = 1

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

type CtrlRequest struct {
	Host          Host
	LocalStreamId uint32
}
type CtrlResponse struct {
	Success       bool
	LocalStreamId uint32
	Message       string
}

type Ctrl struct {
	waitRequestCountChan chan int
	ctrlRequestChan      chan *CtrlRequest
}

// LocalStream wraps local connection, accepted or initiated
type LocalStream struct {
	conn      io.ReadWriteCloser
	Id        uint32
	bytesChan chan []byte //

	syncChan chan bool // channel for flow control

	// to hold packets resent to WritePackList, Keep packet buffers in the link.

	ringBufW *RingBuf // Buffer for write.
	ringBufR *RingBuf // Buffer for read.
	ReadNo   int64    // number of packets read in this session
	WriteNo  int64    // number of packets written in this session

	ctrlRespChan chan *CtrlResponse
}

func (ts *LocalStream) String() string {
	return fmt.Sprintf("LocalStream(id: %d, syncChan len: %d, rxSeq: %d, tx: %d)",
		ts.Id, len(ts.syncChan), ts.ReadNo, ts.WriteNo)
}

const Session_state_authchallenge = "authchallenge"
const Session_state_authresponse = "authresponse"
const Session_state_authresult = "authresult"
const Session_state_authmiss = "authmiss"
const Session_state_header = "ctrlRequestChan"
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

	localStreamMap     map[uint32]*LocalStream
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
		session.localStreamMap[count] = NewLocalStream(nil, count)
	}

	session.ctrl.waitRequestCountChan = make(chan int, 100)
	session.ctrl.ctrlRequestChan = make(chan *CtrlRequest, 1)
	//sessionInfo.ctrl.ctrlRespChan = make(chan *CtrlResponse,1)

	for count := 0; count < PACKET_NUM_DIV; count++ {
		session.encSyncChan <- true
	}
}

func newEmptySession(sessionId int, token string, isTunnelServer bool) *Session {
	sessionInfo := &Session{
		Id:                 sessionId,
		Token:              token,
		packetChan:         make(chan Packet, PACKET_NUM),
		packetEncChan:      make(chan Packet, PACKET_NUM),
		readSize:           0,
		wroteSize:          0,
		localStreamMap:     map[uint32]*LocalStream{},
		nextTunnelStreamId: TUNNEL_STREAM_ID_USR,
		ReadNo:             0,
		WriteNo:            0,
		WritePackList:      new(list.List),
		RewriteNo:          -1,
		ctrl:               Ctrl{},
		state:              "None",
		isTunnelServer:     isTunnelServer,
		ringBufEnc:         NewRingBuf(PACKET_NUM, BUFSIZE),
		encSyncChan:        make(chan bool, PACKET_NUM_DIV),
		reconnetWaitState:  0,
		releaseChan:        make(chan bool, 3),
		mutex:              &Lock{},
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
		fmt.Fprintf(stream, "localStreamMap: %d\n", len(sessionInfo.localStreamMap))

		for _, citi := range sessionInfo.localStreamMap {
			fmt.Fprintf(stream, "======\n")
			fmt.Fprintf(stream, "Id: %d-%d\n", sessionInfo.Id, citi.Id)
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
	sessionInfo := newEmptySession(nextSessionId, token, isTunnelServer)
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

func NewLocalStream(conn io.ReadWriteCloser, citiId uint32) *LocalStream {
	tunnelStream := &LocalStream{
		conn:         conn,
		Id:           citiId,
		bytesChan:    make(chan []byte, PACKET_NUM),
		syncChan:     make(chan bool, PACKET_NUM_DIV),
		ringBufW:     NewRingBuf(PACKET_NUM, BUFSIZE),
		ringBufR:     NewRingBuf(PACKET_NUM, BUFSIZE),
		ReadNo:       0,
		WriteNo:      0,
		ctrlRespChan: make(chan *CtrlResponse),
	}
	for count := 0; count < PACKET_NUM_DIV; count++ {
		tunnelStream.syncChan <- true
	}
	return tunnelStream
}

func (session *Session) getCtrlRequest() *CtrlRequest {
	ctrl := session.ctrl

	ctrl.waitRequestCountChan <- 0
	header := <-ctrl.ctrlRequestChan
	<-ctrl.waitRequestCountChan

	return header
}

func (session *Session) addTunnelStream(conn io.ReadWriteCloser, tunnelStreamId uint32) *LocalStream {
	sessionMgr.mutex.get("addTunnelStream")
	defer sessionMgr.mutex.rel()

	if tunnelStreamId == TUNNEL_STREAM_ID_CTRL {
		tunnelStreamId = session.nextTunnelStreamId
		session.nextTunnelStreamId++
		if session.nextTunnelStreamId <= TUNNEL_STREAM_ID_USR {
			log.Fatal().Msg("tunnelStream id overflows")
		}
	}

	tunnelStream, exists := session.localStreamMap[tunnelStreamId]
	if exists {
		log.Info().Int("sessionId", session.Id).Msgf("tsId %d exists", tunnelStreamId)
		return tunnelStream
	}

	tunnelStream = NewLocalStream(conn, tunnelStreamId)
	session.localStreamMap[tunnelStreamId] = tunnelStream
	log.Info().Int("sessionId", session.Id).
		Msgf("tunnelStream added, streamId: %d, tunnelStream total: %d", tunnelStreamId, len(session.localStreamMap))
	if len(session.localStreamMap) > 0 {
		for tsId, ts := range session.localStreamMap {
			log.Debug().Msgf("%d => %s", tsId, ts.String())
		}
	}
	return tunnelStream
}

func (session *Session) getTunnelStream(tunnelStreamId uint32) *LocalStream {
	sessionMgr.mutex.get("getTunnelStream")
	defer sessionMgr.mutex.rel()

	if tunnelStream, exists := session.localStreamMap[tunnelStreamId]; exists {
		return tunnelStream
	}
	return nil
}

func (session *Session) delTunnelStream(localStream *LocalStream) {
	sessionMgr.mutex.get("delTunnelStream")
	defer sessionMgr.mutex.rel()

	delete(session.localStreamMap, localStream.Id)
	log.Info().Int("sessionId", session.Id).Uint32("localStreamId", localStream.Id).
		Msgf("streamId deleted, left total: %d", len(session.localStreamMap))

	log.Info().Int("sessionId", session.Id).Uint32("localStreamId", localStream.Id).
		Msgf("discard bytesChan, total: %d", len(localStream.bytesChan))
	for len(localStream.bytesChan) > 0 {
		<-localStream.bytesChan
	}
}

func (session *Session) hasTunnelStream() bool {
	sessionMgr.mutex.get("hasTunnelStream")
	defer sessionMgr.mutex.rel()
	return len(session.localStreamMap) > TUNNEL_STREAM_ID_USR
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
	sessionsByToken map[string]*Session // session token => session
	transportMap    map[int]*Transport  // sessionId => transport
	muxMap          map[int]*Mux        // sessionId => transport
	mutex           Lock                // mutex when accessing values in the SessionManager
}

// TODO global variable, remove this
var sessionMgr = SessionManager{
	sessionsByToken: map[string]*Session{},
	transportMap:    map[int]*Transport{},
	muxMap:          map[int]*Mux{},
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

type Packet struct {
	kind     int8 // PACKET_KIND_*
	streamId uint32
	bytes    []byte // write data
}

func (pkt *Packet) String() string {
	if pkt.kind == PACKET_KIND_SYNC && len(pkt.bytes) > 8 {
		return fmt.Sprintf("Packet(kind: %s, seq: %d, streamId: %d, bytes: %d bytes/%p)",
			getKindName(pkt.kind), int64(binary.BigEndian.Uint64(pkt.bytes)), pkt.streamId, len(pkt.bytes), pkt.bytes)
	}
	if pkt.kind == PACKET_KIND_NORMAL && pkt.streamId == TUNNEL_STREAM_ID_CTRL {
		return fmt.Sprintf("Packet(kind: %s, streamId: %d/ctrl, bytes: %d bytes/%p)", getKindName(pkt.kind), pkt.streamId, len(pkt.bytes), pkt.bytes)
	}
	return fmt.Sprintf("Packet(kind: %s, streamId: %d, bytes: %d bytes/%p)", getKindName(pkt.kind), pkt.streamId, len(pkt.bytes), pkt.bytes)
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

// parses control packet from binary
func handleControlPacket(session *Session, payloadBuf []byte) {
	if len(payloadBuf) == 0 {
		log.Print("ignore empty buffer 0")
		return
	}
	ctrlHeaderKind := payloadBuf[0]
	body := payloadBuf[1:]

	var buffer bytes.Buffer
	buffer.Write(body)

	switch ctrlHeaderKind {
	case CTRL_REQ_NEW_CONNECTION:
		header := CtrlRequest{}
		if err := json.NewDecoder(&buffer).Decode(&header); err != nil {
			log.Fatal().Err(err).Msgf("fail to parse ctrlRequestChan")
		}
		session.ctrl.ctrlRequestChan <- &header // bytes from conn, now this control request header is pushed into chan
		log.Info().Msgf("LocalStream ctrl_req pushed ctrlRequestChan")
	case CTRL_RESP_CONNECTION_ESTABLISHED:
		resp := CtrlResponse{}
		if err := json.NewDecoder(&buffer).Decode(&resp); err != nil {
			log.Fatal().Msgf("failed to read ctrlRequestChan: %v", err)
		}
		if tunnelStream := session.getTunnelStream(resp.LocalStreamId); tunnelStream != nil {
			tunnelStream.ctrlRespChan <- &resp
			log.Info().Msgf("streamId: %d, ctrl_resp pushed to stream's ctrlRespChan", tunnelStream.Id)
		} else {
			log.Error().Msgf("stream %d not found, ctrl_resp is discarded", resp.LocalStreamId)
		}
	}
}

func reconnectAndRewrite(info *Mux, connInfoRev *ConnInfoRev) bool {
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

func packetEncrypterGR(mux *Mux) {
	transport := mux.transport
	session := transport.Session

	packChan := session.packetChan
	ringBufEnc := session.ringBufEnc
	encSyncChan := session.encSyncChan

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
			if transport.CryptCtrl != nil {
				packet.bytes = transport.CryptCtrl.enc.Process(packet.bytes, buf)
			}
		}

		session.packetEncChan <- packet
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
		writeErr = transport.writeSyncPacket(writer, pkt.streamId, pkt.bytes)
		log.Debug().Int("sessionId", sessionId).Msgf("sync sent")
	case PACKET_KIND_NORMAL:
		writeErr = transport.writeNormalPacket(writer, pkt.streamId, pkt.bytes)
	case PACKET_KIND_NORMAL_DIRECT:
		writeErr = transport.writeNormalDirectPacket(writer, pkt.streamId, pkt.bytes)
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

func keepaliveGR(mux *Mux, interval int) {
	session := mux.transport.Session
	log.Info().Int("sessionId", session.Id).Msgf("start keepaliveGR routine ...")

	// TODO update this to a better way
	for !mux.shouldEnd {
		for sleepTime := 0; sleepTime < interval; sleepTime += KeepaliveSleepMs {
			time.Sleep(KeepaliveSleepMs * time.Millisecond)
			if mux.shouldEnd {
				break
			}
		}
		if !mux.isConnecting {
			session.packetChan <- Packet{kind: PACKET_KIND_DUMMY, streamId: TUNNEL_STREAM_ID_CTRL}
		}
	}
	log.Info().Int("sessionId", session.Id).Msgf("keepaliveGR routine exits")
}

// KeepaliveSleepMs interval for keepaliveGR check
// If this is long, it takes time to wait for relayLocalTransport post-processing.
// If it's short, it will be heavy.
const KeepaliveSleepMs = 500

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

type LocalListener struct {
	listener Listener
	forward  Forward
}

func (listener *LocalListener) Close() {
	_ = listener.listener.Close()
}

type ListenerGroup struct {
	listeners []LocalListener
}

func (group *ListenerGroup) Close() {
	for _, info := range group.listeners {
		info.Close()
	}
}

func NewListen(isClient bool, forwardList []Forward) (*ListenerGroup, []Forward) {
	return NewListenWithMaker(isClient, forwardList, func(dst string) (Listener, error) {
		listen, err := net.Listen("tcp", dst)
		if err != nil {
			return nil, err
		}
		return &NetListener{listen}, nil
	})
}

func NewListenWithMaker(isClient bool, forwardList []Forward, listenMaker func(dst string) (Listener, error)) (*ListenerGroup, []Forward) {
	listenGroup := ListenerGroup{listeners: []LocalListener{}}
	var localForwards []Forward

	for _, forwardInfo := range forwardList {
		if (isClient && !forwardInfo.IsReverse) || (!isClient && forwardInfo.IsReverse) {
			local, err := listenMaker(forwardInfo.Src.String())
			if err != nil {
				log.Fatal().Err(err)
				return nil, []Forward{}
			}
			listenGroup.listeners = append(listenGroup.listeners, LocalListener{local, forwardInfo})
			log.Printf("add to listener listenGroup: %s", forwardInfo.String())
		} else {
			localForwards = append(localForwards, forwardInfo)
			log.Printf("add to local forwards: %s", forwardInfo.String())
		}
	}

	return &listenGroup, localForwards
}

// ListenAndNewConnect waits for a session to pass through Tunnel & connect to the communication destination of the session
// @param transport Tunnel
// @param port Listening port number
// @param parm tunnel information
// @param reconnect reconnection function
func ListenAndNewConnect(isClient bool, listenGroup *ListenerGroup, localForwardList []Forward, connInfo *Transport, param *TunnelParam, reconnect func(sessionInfo *Session) *Transport) {
	ListenAndNewConnectWithDialer(isClient, listenGroup, localForwardList, connInfo, param, reconnect, func(dst string) (io.ReadWriteCloser, error) {
		log.Info().Msgf("dial %s", dst)
		return net.Dial("tcp", dst)
	})
}

func ListenAndNewConnectWithDialer(isClient bool, listenerGroup *ListenerGroup, localForwards []Forward, transport *Transport, param *TunnelParam,
	reconnect func(session *Session) *Transport, dialer func(dst string) (io.ReadWriteCloser, error)) {
	mux, isSessionNew := newMux(transport, len(listenerGroup.listeners) > 0, reconnect) // mux created

	session := transport.Session
	session.SetState(Session_state_connected)
	if isSessionNew {
		log.Info().Int("sessionId", session.Id).Msgf("new session, launch mux reader/writer routines ...")
		go readTunnelTransportGR(mux)  // transport read: tunnelStream bytesChan <= transport conn
		go writeTunnelTransportGR(mux) // transport write: session packetChan => transport conn
		if PRE_ENC {
			go packetEncrypterGR(mux)
		}
		go keepaliveGR(mux, param.KeepAliveInterval)
	}

	for _, listener := range listenerGroup.listeners {
		go acceptAndRelayForeverGR(listener, mux.transport.Session) // start each listening in the listenerGroup
	}

	log.Debug().Msgf("start local forwards ...")
	if len(localForwards) > 0 {
		for {
			ctrlRequest := session.getCtrlRequest()
			if ctrlRequest == nil {
				log.Info().Msgf("receive nil ctrlRequest, exit the local forwarding loop")
				break
			}
			destAddr := ctrlRequest.Host.String()
			streamId := ctrlRequest.LocalStreamId
			log.Debug().Msgf("get non-nil ctrlRequest, initiate a new connection now ...")
			go establishNewConnection(dialer, destAddr, streamId, session) // create new connection and mux
		}
		log.Debug().Msgf("local forwards ended")
	}

	waitListenerGroupExit(isClient, session, listenerGroup)
	log.Debug().Msgf("disconnected")
	session.SetState(Session_state_disconnected)
}

func waitListenerGroupExit(isClient bool, session *Session, listenerGroup *ListenerGroup) {
	log.Debug().Msgf("waiting listener group exiting ...")
	if len(listenerGroup.listeners) == 0 {
		log.Debug().Msgf("no listeners to wait")
		return
	}
	for {
		log.Debug().Msgf("wait for releaseChan")
		if !<-session.releaseChan {
			break
		}
		log.Debug().Msgf("client side: %t", isClient)
		if !isClient {
			break
		}
	}
	log.Debug().Msgf("local listeners ended")
}

// sends a dummy(nil) ctrlRequestChan to avoid waiting
func reverseTunnelPreCloseHook(info *Mux) {
	sessionInfo := info.transport.Session

	log.Info().Msgf("sessionId: %d, pre close action, is reverse tunnel: %t", sessionInfo.Id, sessionInfo.isTunnelServer)
	if sessionInfo.isTunnelServer {
		for len(sessionInfo.ctrl.waitRequestCountChan) > 0 {
			count := len(sessionInfo.ctrl.waitRequestCountChan)
			for index := 0; index < count; index++ {
				sessionInfo.ctrl.ctrlRequestChan <- nil // send a dummy to avoid waiting for connection
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
