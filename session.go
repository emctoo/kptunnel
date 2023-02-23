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

// tunnel 上に通す tcp の組み合わせ
type ForwardInfo struct {
	// これが reverse tunnel の場合 true
	IsReverseTunnel bool
	// listen する host:port
	Src HostInfo
	// forward する相手の host:port
	Dst HostInfo
}

func (info *ForwardInfo) String() string {
	return fmt.Sprintf("ForwardInfo(reverse: %t, %s => %s)", info.IsReverseTunnel, info.Src.String(), info.Dst.String())
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
	ServerInfo HostInfo
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

const CITIID_CTRL = 0
const CITIID_USR = 1

const CTRL_HEADER = 0
const CTRL_RESP_HEADER = 1

// 再接続後の CryptCtrlObj を同じものを使えるようにするまで true には出来ない
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

type ConnHeader struct {
	HostInfo HostInfo
	CitiId   uint32
}
type CtrlRespHeader struct {
	Result bool
	Mess   string
	CitiId uint32
}

type CtrlInfo struct {
	waitHeaderCount chan int
	header          chan *ConnHeader
}

type ConnInTunnelInfo struct {
	conn            io.ReadWriteCloser
	citiId          uint32
	sourceBytesChan chan []byte
	end             bool

	syncChan chan bool // channel for flow control

	// to hold packets resent to WritePackList, Keep packet buffers in the link.

	ringBufW  *RingBuf // Buffer for write.
	ringBufR  *RingBuf // Buffer for read.
	ReadNo    int64    // number of packets read in this session
	WriteNo   int64    // number of packets written in this session
	ReadSize  int64
	WriteSize int64

	respHeader chan *CtrlRespHeader

	ReadState  int
	WriteState int

	waitTimeInfo WaitTimeInfo
}

const Session_state_authchallenge = "authchallenge"
const Session_state_authresponse = "authresponse"
const Session_state_authresult = "authresult"
const Session_state_authmiss = "authmiss"
const Session_state_header = "header"
const Session_state_respheader = "respheader"
const Session_state_connected = "connected"
const Session_state_reconnecting = "reconnecting"
const Session_state_disconnected = "disconnected"

type WaitTimeInfo struct {
	stream2Tunnel time.Duration
	tunnel2Stream time.Duration
	packetReader  time.Duration
}

// セッションの情報
type SessionInfo struct {
	// セッションを識別する ID
	SessionId    int
	SessionToken string

	// packet 書き込み用 channel
	packChan    chan PackInfo
	packChanEnc chan PackInfo

	// pipe から読み取ったサイズ
	readSize int64
	// pipe に書き込んだサイズ
	wroteSize int64

	citiId2Info map[uint32]*ConnInTunnelInfo
	nextCtitId  uint32

	// このセッションで read したパケットの数
	ReadNo int64
	// このセッションで write したパケットの数
	WriteNo int64

	// 送信した SessionPacket のリスト。
	// 直近 PACKET_NUM 分の SessionPacket を保持する。
	WritePackList *list.List

	// 送り直すパケット番号。
	// -1 の場合は送り直しは無し。
	ReWriteNo int64

	ctrlInfo CtrlInfo

	state string

	isTunnelServer bool

	ringBufEnc  *RingBuf
	encSyncChan chan bool

	packetWriterWaitTime time.Duration

	readState  int
	writeState int

	// reconnet を待っている状態。
	// 0: 待ち無し, 1: read or write どちらかで待ち,  2: read/write 両方で待ち
	reconnetWaitState int

	releaseChan chan bool

	// この構造体のメンバアクセス排他用 mutex
	mutex *Lock
}

func (session *SessionInfo) GetPacketBuf(citiId uint32, packSize uint16) []byte {
	if citiId >= CITIID_USR {
		if citi := session.getCiti(citiId); citi != nil {
			buf := citi.ringBufR.getCur()
			if len(buf) < int(packSize) {
				log.Fatal().Msgf("illegal packet size: %d", len(buf))
			}
			return buf[:packSize]
		}
	}
	return make([]byte, packSize)
}

func (session *SessionInfo) SetState(state string) {
	session.state = state
}

func (session *SessionInfo) Setup() {
	for count := uint32(0); count < CITIID_USR; count++ {
		session.citiId2Info[count] = NewConnInTunnelInfo(nil, count)
	}

	session.ctrlInfo.waitHeaderCount = make(chan int, 100)
	session.ctrlInfo.header = make(chan *ConnHeader, 1)
	//sessionInfo.ctrlInfo.respHeader = make(chan *CtrlRespHeader,1)

	for count := 0; count < PACKET_NUM_DIV; count++ {
		session.encSyncChan <- true
	}
}

func newEmptySessionInfo(
	sessionId int, token string, isTunnelServer bool) *SessionInfo {
	sessionInfo := &SessionInfo{
		SessionId:            sessionId,
		SessionToken:         token,
		packChan:             make(chan PackInfo, PACKET_NUM),
		packChanEnc:          make(chan PackInfo, PACKET_NUM),
		readSize:             0,
		wroteSize:            0,
		citiId2Info:          map[uint32]*ConnInTunnelInfo{},
		nextCtitId:           CITIID_USR,
		ReadNo:               0,
		WriteNo:              0,
		WritePackList:        new(list.List),
		ReWriteNo:            -1,
		ctrlInfo:             CtrlInfo{},
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
	for _, sessionInfo := range sessionMgr.sessionToken2info {
		fmt.Fprintf(stream, "sessionId: %d\n", sessionInfo.SessionId)
		fmt.Fprintf(stream, "token: %s\n", sessionInfo.SessionToken)
		fmt.Fprintf(stream, "state: %s\n", sessionInfo.state)
		fmt.Fprintf(stream, "mutex onwer: %s\n", sessionInfo.mutex.owner)
		fmt.Fprintf(
			stream, "WriteNo, ReadNo: %d %d\n",
			sessionInfo.WriteNo, sessionInfo.ReadNo)
		fmt.Fprintf(stream, "packChan: %d\n", len(sessionInfo.packChan))
		fmt.Fprintf(stream, "packChanEnc: %d\n", len(sessionInfo.packChanEnc))
		fmt.Fprintf(stream, "encSyncChan: %d\n", len(sessionInfo.encSyncChan))
		// fmt.Fprintf(stream, "releaseChan: %d\n", len(sessionInfo.releaseChan))
		fmt.Fprintf(
			stream, "writeSize, ReadSize: %d, %d\n",
			sessionInfo.wroteSize, sessionInfo.readSize)
		fmt.Fprintf(stream, "citiId2Info: %d\n", len(sessionInfo.citiId2Info))
		fmt.Fprintf(
			stream, "readState %d, writeState %d\n",
			sessionInfo.readState, sessionInfo.writeState)

		for _, citi := range sessionInfo.citiId2Info {
			fmt.Fprintf(stream, "======\n")
			fmt.Fprintf(stream, "citiId: %d-%d\n", sessionInfo.SessionId, citi.citiId)
			fmt.Fprintf(
				stream, "readState %d, writeState %d\n",
				citi.ReadState, citi.WriteState)
			fmt.Fprintf(
				stream, "syncChan: %d, sourceBytesChan %d, readNo %d, writeNo %d\n",
				len(citi.syncChan), len(citi.sourceBytesChan), citi.ReadNo, citi.WriteNo)
		}

		fmt.Fprintf(stream, "------------\n")
	}
}

var nextSessionId = 0

func NewSessionInfo(isTunnelServer bool) *SessionInfo {
	sessionMgr.mutex.get("NewSessionInfo")
	defer sessionMgr.mutex.rel()

	nextSessionId++

	randbin := make([]byte, 9)
	if _, err := io.ReadFull(rand.Reader, randbin); err != nil {
		panic(err.Error())
	}
	token := base64.StdEncoding.EncodeToString(randbin)
	sessionInfo := newEmptySessionInfo(nextSessionId, token, isTunnelServer)
	sessionMgr.sessionToken2info[sessionInfo.SessionToken] = sessionInfo

	return sessionInfo
}

func (session *SessionInfo) UpdateSessionId(sessionId int, token string) {
	sessionMgr.mutex.get("UpdateSessionId")
	defer sessionMgr.mutex.rel()

	session.SessionId = sessionId
	session.SessionToken = token
	sessionMgr.sessionToken2info[session.SessionToken] = session
}

func NewConnInTunnelInfo(conn io.ReadWriteCloser, citiId uint32) *ConnInTunnelInfo {
	citi := &ConnInTunnelInfo{
		conn:            conn,
		citiId:          citiId,
		sourceBytesChan: make(chan []byte, PACKET_NUM),
		end:             false,
		syncChan:        make(chan bool, PACKET_NUM_DIV),
		ringBufW:        NewRingBuf(PACKET_NUM, BUFSIZE),
		ringBufR:        NewRingBuf(PACKET_NUM, BUFSIZE),
		ReadNo:          0,
		WriteNo:         0,
		ReadSize:        0,
		WriteSize:       0,
		respHeader:      make(chan *CtrlRespHeader),
		ReadState:       0,
		WriteState:      0,
		waitTimeInfo:    WaitTimeInfo{},
	}
	for count := 0; count < PACKET_NUM_DIV; count++ {
		citi.syncChan <- true
	}
	return citi
}

// get control header
func (session *SessionInfo) getHeader() *ConnHeader {
	ctrlInfo := session.ctrlInfo
	ctrlInfo.waitHeaderCount <- 0
	header := <-ctrlInfo.header
	<-ctrlInfo.waitHeaderCount
	return header
}

func (session *SessionInfo) addCiti(role string, conn io.ReadWriteCloser, citiId uint32) *ConnInTunnelInfo {
	sessionMgr.mutex.get("addCiti")
	defer sessionMgr.mutex.rel()

	if citiId == CITIID_CTRL {
		citiId = session.nextCtitId
		session.nextCtitId++
		if session.nextCtitId <= CITIID_USR {
			log.Fatal().Str("role", role).Msg("citId overflows")
		}
	}

	citi, exists := session.citiId2Info[citiId]
	if exists {
		log.Info().Str("role", role).Int("sessionId", session.SessionId).Msgf("cit %d exists Citi", citiId)
		return citi
	}

	citi = NewConnInTunnelInfo(conn, citiId)
	session.citiId2Info[citiId] = citi
	log.Info().Str("role", role).Int("sessionId", session.SessionId).Msgf("cit added, citId: %d, cit total: %d", citiId, len(session.citiId2Info))
	return citi
}

func (session *SessionInfo) getCiti(citiId uint32) *ConnInTunnelInfo {
	sessionMgr.mutex.get("getCiti")
	defer sessionMgr.mutex.rel()

	if citi, has := session.citiId2Info[citiId]; has {
		return citi
	}
	return nil
}

func (session *SessionInfo) delCiti(citi *ConnInTunnelInfo) {
	sessionMgr.mutex.get("delCiti")
	defer sessionMgr.mutex.rel()

	delete(session.citiId2Info, citi.citiId)

	log.Printf(
		"delCiti -- %d %d %d", session.SessionId, citi.citiId, len(session.citiId2Info))

	// 詰まれているデータを読み捨てる
	log.Printf("delCiti discard sourceBytesChan -- %d", len(citi.sourceBytesChan))
	for len(citi.sourceBytesChan) > 0 {
		<-citi.sourceBytesChan
	}
}

func (session *SessionInfo) hasCiti() bool {
	sessionMgr.mutex.get("hasCiti")
	defer sessionMgr.mutex.rel()

	log.Printf("hasCiti -- %d %d", session.SessionId, len(session.citiId2Info))

	return len(session.citiId2Info) > CITIID_USR
}

// コネクション情報
type ConnInfo struct {
	// コネクション
	Conn io.ReadWriteCloser
	// 暗号化情報
	CryptCtrlObj *CryptCtrl
	// セッション情報
	SessionInfo *SessionInfo
	writeBuffer bytes.Buffer
}

// ConnInfo の生成
//
// @param conn コネクション
// @param pass 暗号化パスワード
// @param count 暗号化回数
// @param sessionInfo セッション情報
// @return ConnInfo
func CreateConnInfo(
	conn io.ReadWriteCloser, pass *string, count int,
	sessionInfo *SessionInfo, isTunnelServer bool) *ConnInfo {
	if sessionInfo == nil {
		sessionInfo = newEmptySessionInfo(0, "", isTunnelServer)
	}
	return &ConnInfo{
		conn, CreateCryptCtrl(pass, count), sessionInfo, bytes.Buffer{}}
}

// 再送信パケット番号の送信
//
// @param readNo 接続先の読み込み済みパケット No
func (session *SessionInfo) SetReWrite(readNo int64) {
	if session.WriteNo > readNo {
		// こちらが送信したパケット数よりも相手が受け取ったパケット数が少ない場合、
		// パケットを再送信する。
		session.ReWriteNo = readNo
	} else if session.WriteNo == readNo {
		// こちらが送信したパケット数と、相手が受け取ったパケット数が一致する場合、
		// 再送信はなし。
		session.ReWriteNo = -1
	} else {
		// こちらが送信したパケット数よりも相手が受け取ったパケット数が多い場合、
		// そんなことはありえないのでエラー
		log.Fatal().Msg("mismatch WriteNo")
	}
}

// セッション管理
type sessionManager struct {
	// sessionID -> SessionInfo のマップ
	sessionToken2info map[string]*SessionInfo
	// sessionID -> ConnInfo のマップ
	sessionId2conn map[int]*ConnInfo
	// sessionID -> PipeInfo のマップ
	sessionId2pipe map[int]*PipeInfo
	// コネクションでのセッションが有効化どうかを判断するためのマップ。
	// channel を使った方がスマートに出来そうな気がする。。
	conn2alive map[io.ReadWriteCloser]bool
	// sessionManager 内の値にアクセスする際の mutex
	mutex Lock
}

var sessionMgr = sessionManager{
	map[string]*SessionInfo{},
	map[int]*ConnInfo{},
	map[int]*PipeInfo{},
	map[io.ReadWriteCloser]bool{},
	Lock{}}

// 指定のコネクションをセッション管理に登録する
func SetSessionConn(connInfo *ConnInfo) {
	sessionId := connInfo.SessionInfo.SessionId
	log.Printf("set session %d conn", sessionId)

	sessionMgr.mutex.get("SetSessionConn")
	defer sessionMgr.mutex.rel()

	sessionMgr.sessionId2conn[connInfo.SessionInfo.SessionId] = connInfo
	sessionMgr.conn2alive[connInfo.Conn] = true
}

// 指定のセッション token  に紐付けられた SessionInfo を取得する
func GetSessionInfo(token string) (*SessionInfo, bool) {
	sessionMgr.mutex.get("GetSessionInfo")
	defer sessionMgr.mutex.rel()

	sessionInfo, has := sessionMgr.sessionToken2info[token]
	return sessionInfo, has
}

// PipeInfo controls information that relays communication between tunnel and connection destination
type PipeInfo struct {
	rev int // Revision of connInfo. Counts up each time reconnection is established.

	// reconnect function
	//
	// @param sessionInfo session information
	// @return *ConnInfo Connected connection.
	// - nil if unable to reconnect.
	// Retry reconnection in this function.
	// If this function returns nil, give up reconnection.
	reconnectFunc func(sessionInfo *SessionInfo) *ConnInfo

	end        bool      // true when this Tunnel connection should be terminated
	fin        chan bool // Channel for waiting for the end of relay processing
	connecting bool      // true while reconnecting
	connInfo   *ConnInfo // Connection information connecting pipe
	// reconnected chan bool //

	citServerFlag bool // true if citi is server
}

func (pipe *PipeInfo) sendRelease() {
	if pipe.citServerFlag {
		releaseChan := pipe.connInfo.SessionInfo.releaseChan //
		if len(releaseChan) == 0 {
			releaseChan <- true
		}
	}
}

type PackInfo struct {
	// 書き込みデータ
	bytes []byte
	// PACKET_KIND_*
	kind   int8
	citiId uint32
}

// セッションで書き込んだデータを保持する
type SessionPacket struct {
	// パケット番号
	no   int64
	pack PackInfo
}

func (session *SessionInfo) postWriteData(packInfo *PackInfo) {
	list := session.WritePackList
	list.PushBack(SessionPacket{no: session.WriteNo, pack: *packInfo})
	if list.Len() > PACKET_NUM {
		list.Remove(list.Front())
	}
	if PRE_ENC {
		if (session.WriteNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 {
			session.encSyncChan <- true
		}
	}
	session.WriteNo++
	session.wroteSize += int64(len(packInfo.bytes))
}

// コネクションへのデータ書き込み
//
// ここで、書き込んだデータを WritePackList に保持する。
//
// @param info コネクション
// @param bytes 書き込みデータ
// @return error 失敗した場合 error
func (info *ConnInfo) writeData(stream io.Writer, citiId uint32, bytes []byte) error {
	if !PRE_ENC {
		if err := WriteItem(
			stream, citiId, bytes, info.CryptCtrlObj, &info.writeBuffer); err != nil {
			return err
		}
	} else {
		if err := WriteItem(
			stream, citiId, bytes, nil, &info.writeBuffer); err != nil {
			return err
		}
	}
	return nil
}

func (info *ConnInfo) writeDataDirect(stream io.Writer, citiId uint32, bytes []byte) error {
	if !PRE_ENC {
		if err := WriteItemDirect(stream, citiId, bytes, info.CryptCtrlObj); err != nil {
			return err
		}
	} else {
		if err := WriteItemDirect(stream, citiId, bytes, nil); err != nil {
			return err
		}
	}
	return nil
}

// コネクションからのデータ読み込み
//
// @param info コネクション
// @param work 作業用バッファ
// @return error 失敗した場合 error
func (info *ConnInfo) readData(work []byte) (*PackItem, error) {
	var item *PackItem
	var err error

	for {
		item, err = ReadItem(info.Conn, info.CryptCtrlObj, work, info.SessionInfo)
		if err != nil {
			return nil, err
		}
		if item.kind != PACKET_KIND_DUMMY {
			info.SessionInfo.ReadNo++
		}
		if item.kind == PACKET_KIND_NORMAL {
			break
		}
		switch item.kind {
		case PACKET_KIND_SYNC:
			packNo := int64(binary.BigEndian.Uint64(item.buf))

			log.Debug().Msgf("%d - get sync ", packNo)
			// 相手が受けとったら syncChan を更新して、送信処理を進められるように設定
			if citi := info.SessionInfo.getCiti(item.citiId); citi != nil {
				citi.syncChan <- true
			} else {
				log.Debug().Msgf("cit %d not found, discard sync packet", item.citiId)
			}
		}
	}
	info.SessionInfo.readSize += int64(len(item.buf))
	return item, nil
}

// 再接続を行なう
//
// @param rev 現在のリビジョン
// @return ConnInfo 再接続後のコネクション
// @return int 再接続後のリビジョン
// @return bool セッションを終了するかどうか。終了する場合 true
func (pipe *PipeInfo) reconnect(txt string, rev int) (*ConnInfo, int, bool) {

	workRev, workConnInfo := pipe.getConn()
	sessionInfo := pipe.connInfo.SessionInfo

	sessionInfo.mutex.get("reconnect")
	sessionInfo.reconnetWaitState++
	sessionInfo.mutex.rel()

	log.Printf("reconnect -- rev: %s, %d %d, %p", txt, rev, workRev, workConnInfo)

	reqConnect := false

	sub := func() bool {
		sessionInfo.mutex.get("reconnect-sub")
		defer sessionInfo.mutex.rel()

		if pipe.rev != rev {
			if !pipe.connecting {
				sessionInfo.reconnetWaitState--
				workRev = pipe.rev
				workConnInfo = pipe.connInfo
				return true
			}
		} else {
			pipe.connecting = true
			pipe.rev++
			reqConnect = true
			return true
		}
		return false
	}

	if pipe.reconnectFunc != nil {
		for {
			if sub() {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}
	} else {
		reqConnect = true
		pipe.rev++
	}

	if reqConnect {
		releaseSessionConn(pipe)
		reverseTunnelPreCloseHook(pipe)

		if len(sessionInfo.packChan) == 0 {
			// sessionInfo.packChan 待ちで packetWriter が止まらないように
			// dummy を投げる。
			sessionInfo.packChan <- PackInfo{nil, PACKET_KIND_DUMMY, CITIID_CTRL}
		}

		if !pipe.end {
			sessionInfo.SetState(Session_state_reconnecting)

			workRev = pipe.rev
			workInfo := pipe.reconnectFunc(sessionInfo)
			if workInfo != nil {
				pipe.connInfo = workInfo
				log.Printf("new connInfo -- %p", workInfo)
				sessionInfo.SetState(Session_state_connected)
			} else {
				pipe.end = true
				pipe.connInfo = CreateConnInfo(dummyConn, nil, 0, sessionInfo, sessionInfo.isTunnelServer)
				log.Printf("set dummyConn")
			}
			workConnInfo = pipe.connInfo

			func() {
				sessionInfo.mutex.get("reconnectFunc-end")
				defer sessionInfo.mutex.rel()
				sessionInfo.reconnetWaitState--
			}()

			pipe.connecting = false
		}
	}

	log.Printf(
		"connected: [%s] rev -- %d, end -- %v, %p",
		txt, workRev, pipe.end, workConnInfo)
	return workConnInfo, workRev, pipe.end
}

// セッションのコネクションを開放する
func releaseSessionConn(info *PipeInfo) {
	connInfo := info.connInfo
	log.Printf("releaseSessionConn -- %d", connInfo.SessionInfo.SessionId)
	sessionMgr.mutex.get("releaseSessionConn")
	defer sessionMgr.mutex.rel()

	delete(sessionMgr.conn2alive, connInfo.Conn)
	delete(sessionMgr.sessionId2conn, connInfo.SessionInfo.SessionId)

	connInfo.Conn.Close()

	info.sendRelease()
}

// 指定のセッションに対応するコネクションを取得する
func GetSessionConn(sessionInfo *SessionInfo) *ConnInfo {
	sessionId := sessionInfo.SessionId
	log.Print("GetSessionConn ... session: ", sessionId)

	sub := func() *ConnInfo {
		sessionMgr.mutex.get("GetSessionConn-sub")
		defer sessionMgr.mutex.rel()

		if connInfo, has := sessionMgr.sessionId2conn[sessionId]; has {
			return connInfo
		}
		return nil
	}
	for {
		if connInfo := sub(); connInfo != nil {
			log.Print("GetSessionConn ok ... session: ", sessionId)
			return connInfo
		}
		// if !sessionInfo.hasCiti() {
		//     log.Print( "GetSessionConn ng ... session: ", sessionId )
		//     return nil
		// }

		time.Sleep(500 * time.Millisecond)
	}
}

// 指定のセッションに対応するコネクションを取得する
func WaitPauseSession(sessionInfo *SessionInfo) bool {
	log.Print("WaitPauseSession start ... session: ", sessionInfo.SessionId)
	sub := func() bool {
		sessionMgr.mutex.get("WaitPauseSession-sub")
		defer sessionMgr.mutex.rel()

		return sessionInfo.reconnetWaitState == 2
	}
	for {
		if sub() {
			log.Print("WaitPauseSession ok ... session: ", sessionInfo.SessionId)
			return true
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// コネクション情報を取得する
//
// @return int リビジョン情報
// @return *ConnInfo コネクション情報
func (pipe *PipeInfo) getConn() (int, *ConnInfo) {
	sessionInfo := pipe.connInfo.SessionInfo
	sessionInfo.mutex.get("getConn")
	defer sessionInfo.mutex.rel()

	return pipe.rev, pipe.connInfo
}

// tunnel stream => conn
func tunnel2Stream(sessionInfo *SessionInfo, destCit *ConnInTunnelInfo, exitChan chan bool) {
	for {
		destCit.ReadState = 10

		waitingTimeStart := time.Now()
		readBuf := <-destCit.sourceBytesChan
		destCit.ReadState = 20
		waitingTime := time.Now().Sub(waitingTimeStart)
		destCit.waitTimeInfo.tunnel2Stream += waitingTime
		if waitingTime > 5*time.Millisecond {
			log.Debug().Msgf("wait bytes channel, readNo: %d, cost: %s", destCit.ReadNo, waitingTime)
		}
		readSize := len(readBuf)
		log.Debug().Msgf("read from bytes channel, readNo: %d, size: %d", destCit.ReadNo, readSize)

		if (destCit.ReadNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 { // send SYNC after reading a certain number
			var buffer bytes.Buffer
			_ = binary.Write(&buffer, binary.BigEndian, destCit.ReadNo)
			destCit.ReadState = 30

			sessionInfo.packChan <- PackInfo{buffer.Bytes(), PACKET_KIND_SYNC, destCit.citiId}
			log.Info().Msg("sync sent to packet chan")
		}
		destCit.ReadNo++
		destCit.ReadSize += int64(len(readBuf))

		if readSize == 0 {
			log.Warn().Msgf("read 0-size from bytes channel, exit")
			break
		}
		destCit.ReadState = 40

		_, writeErr := destCit.conn.Write(readBuf)
		destCit.ReadState = 50

		if writeErr != nil {
			log.Err(writeErr).Msgf("conn writing failed, readNo: %d, exit", destCit.ReadNo)
			break
		}
	}

	sessionInfo.delCiti(destCit) // Remove data from destCit.sourceBytesChan to prevent stuffing
	exitChan <- true
}

// Tunnel へデータの再送を行なう
//
// @param info pipe 情報
// @param connInfo コネクション情報
// @param rev リビジョン
// @return bool 処理を続ける場合 true
func rewirte2Tunnel(info *PipeInfo, connInfoRev *ConnInfoRev) bool {
	// 再接続後にパケットの再送を行なう
	sessionInfo := connInfoRev.connInfo.SessionInfo
	if sessionInfo.ReWriteNo == -1 {
		return true
	}
	log.Printf(
		"rewirte2Tunnel: %d, %d", sessionInfo.WriteNo, sessionInfo.ReWriteNo)
	for sessionInfo.WriteNo > sessionInfo.ReWriteNo {
		item := sessionInfo.WritePackList.Front()
		for ; item != nil; item = item.Next() {
			packet := item.Value.(SessionPacket)
			if packet.no == sessionInfo.ReWriteNo {
				// 再送対象の packet が見つかった
				var err error

				cont := true
				cont, err = writePack(
					&packet.pack, connInfoRev.connInfo.Conn, connInfoRev.connInfo, false)
				if !cont {
					return false
				}
				if err != nil {
					end := false
					connInfoRev.connInfo.Conn.Close()
					connInfoRev.connInfo, connInfoRev.rev, end =
						info.reconnect("rewrite", connInfoRev.rev)
					if end {
						return false
					}
				} else {
					log.Printf(
						"rewrite: %d, %d, %p",
						sessionInfo.ReWriteNo, packet.pack.kind, packet.pack.bytes)
					if sessionInfo.WriteNo == sessionInfo.ReWriteNo {
						sessionInfo.ReWriteNo = -1
					} else {
						sessionInfo.ReWriteNo++
					}
				}
				break
			}
		}
		if item == nil {
			log.Fatal().Msgf("not found packet, RewriteNo: %d", sessionInfo.ReWriteNo)
		}
	}
	return true
}

// conn => tunnel stream
func stream2Tunnel(src *ConnInTunnelInfo, pipeInfo *PipeInfo, fin chan bool) {
	_, connInfo := pipeInfo.getConn()
	sessionInfo := connInfo.SessionInfo
	sessionId := sessionInfo.SessionId
	packChan := sessionInfo.packChan

	end := false
	for !end {
		src.WriteState = 10
		if (src.WriteNo % PACKET_NUM_BASE) == 0 {
			// In order to leave a buffer for retransmission when reconnecting after tunnel disconnection, get syncChan for every PACKET_NUM_BASE
			// Don't send too much when the other party hasn't received it.
			syncWaitingTimeStart := time.Now()
			<-src.syncChan
			span := time.Now().Sub(syncWaitingTimeStart)
			src.waitTimeInfo.stream2Tunnel += span
			if span >= 5*time.Millisecond {
				log.Debug().Int("sessionId", sessionId).Msgf("conn => tunnel stream, span: %s, total span: %s, src writeNo: %d",
					span, src.waitTimeInfo.stream2Tunnel, src.WriteNo)
			}
			log.Debug().Int("sessionId", sessionId).Msgf("get sync packet")
		}
		src.WriteNo++
		src.WriteState = 20

		buf := src.ringBufW.getNext() // switch buffer
		readSize, readErr := src.conn.Read(buf)
		src.WriteState = 30

		log.Debug().Int("sessionId", sessionId).Msgf("conn => tunnel stream, WriteNo: %d, readSize: %d", src.WriteNo, readSize)
		if readErr != nil {
			log.Err(readErr).Int("sessionId", sessionId).Msgf("conn bytes reading err, writeNo: %d", sessionInfo.WriteNo)
			packChan <- PackInfo{make([]byte, 0), PACKET_KIND_NORMAL, src.citiId} // write 0 bytes data to the destination when the input source is dead
			break
		}
		if readSize == 0 {
			log.Warn().Int("sessionId", sessionInfo.SessionId).Msg("ignore 0-size packet")
			continue
		}
		src.WriteSize += int64(readSize)
		src.WriteState = 40

		if (src.WriteNo%PACKET_NUM_BASE) == 0 && len(src.syncChan) == 0 {
			work := <-src.syncChan // if it's the last packet in the packet group and no SYNC is coming, wait for SYNC before sending
			src.syncChan <- work   // Since we read ahead SYNC, we write back SYNC.
		}
		src.WriteState = 50

		packChan <- PackInfo{buf[:readSize], PACKET_KIND_NORMAL, src.citiId}
	}

	fin <- true
}

type ConnInfoRev struct {
	connInfo *ConnInfo
	rev      int
}

// parses control packet from binary
func parseControlPacket(sessionInfo *SessionInfo, buf []byte) {
	if len(buf) == 0 {
		log.Print("ignore empty buffer 0")
		return
	}
	kind := buf[0]
	body := buf[1:]
	var buffer bytes.Buffer
	buffer.Write(body)

	switch kind {
	case CTRL_HEADER:
		header := ConnHeader{}
		if err := json.NewDecoder(&buffer).Decode(&header); err != nil {
			log.Fatal().Err(err).Msgf("fail to parse header")
		}
		sessionInfo.ctrlInfo.header <- &header
		log.Info().Msgf("ctrl header sent to stream")
	case CTRL_RESP_HEADER:
		resp := CtrlRespHeader{}
		if err := json.NewDecoder(&buffer).Decode(&resp); err != nil {
			log.Fatal().Msgf("failed to read header: %v", err)
		}
		if citi := sessionInfo.getCiti(resp.CitiId); citi != nil {
			citi.respHeader <- &resp
			log.Info().Msgf("ctrl response header sent to cit")
		} else {
			log.Error().Msgf("citId %d not found, ctrl response header is discarded", resp.CitiId)
		}
	}
}

func packetReader(pipeInfo *PipeInfo) {
	rev, connInfo := pipeInfo.getConn()
	sessionInfo := connInfo.SessionInfo

	buf := make([]byte, BUFSIZE)
	for {
		readSize := 0
		var citi *ConnInTunnelInfo
		for {
			sessionInfo.readState = 10
			if packet, err := connInfo.readData(buf); err != nil {
				sessionInfo.readState = 20
				log.Err(err).Msgf("fail to read from conn, readNo: %d", sessionInfo.ReadNo)

				end := false
				_ = connInfo.Conn.Close()
				connInfo, rev, end = pipeInfo.reconnect("read", rev)
				if end {
					readSize = 0
					pipeInfo.end = true
					break
				}
			} else {
				sessionInfo.readState = 30
				log.Debug().Msgf("read from conn, size: %d", len(packet.buf))

				if packet.citiId == CITIID_CTRL {
					parseControlPacket(sessionInfo, packet.buf)
					readSize = 1 // set readSize to 1 so that the process doesn't end
				} else {
					if citi = sessionInfo.getCiti(packet.citiId); citi != nil {
						// packet.buf to citi.sourceBytesChan
						// put in and processed in another thread.
						// On the other hand, packet.buf refers to a fixed address, so if you readData before processing in another thread, the contents of packet.buf will be overwritten.
						// Copy to prevent that.

						// cloneBuf := citi.ringBufR.getNext()[:len(packet.buf)]
						// copy( cloneBuf, packet.buf )
						citi.ringBufR.getNext() // TODO comment out this?

						cloneBuf := packet.buf
						waitingTimeStart := time.Now()
						citi.sourceBytesChan <- cloneBuf // TODO buffer is sent over channel, need to copy?
						waitingTime := time.Now().Sub(waitingTimeStart)
						citi.waitTimeInfo.packetReader += waitingTime
						if waitingTime >= 5*time.Millisecond {
							log.Debug().Msgf("get buffer from bytes channel, readNo: %d, cost: %s", citi.ReadNo, waitingTime)
						}
						readSize = len(cloneBuf)
					} else {
						log.Info().Msgf("cit not found: %d, discard the packet", packet.citiId)
						readSize = 1
					}
				}
				if readSize == 0 {
					if packet.citiId == CITIID_CTRL {
						pipeInfo.end = true
					}
				}
				break
			}
		}
		sessionInfo.readState = 40

		if readSize == 0 {
			if citi != nil && len(citi.syncChan) == 0 {
				citi.syncChan <- true // when exiting, stream2Tunnel() may be waiting, notify syncChan here
			}
			sessionInfo.readState = 50

			if pipeInfo.end { // stream ends or read 0-size buffer
				pipeInfo.sendRelease()
				for _, workCiti := range sessionInfo.citiId2Info { // end all tunnel streams
					if len(workCiti.syncChan) == 0 {
						workCiti.syncChan <- true // when exiting, stream2Tunnel() may be waiting, notify syncChan here
					}
				}
				break
			}
		}
	}

	reverseTunnelPreCloseHook(pipeInfo)
	log.Info().Int("sessionId", sessionInfo.SessionId).Msgf("conn reader exits")
	pipeInfo.fin <- true
}

func reconnectAndRewrite(
	info *PipeInfo, connInfoRev *ConnInfoRev) bool {
	end := false
	connInfoRev.connInfo, connInfoRev.rev, end =
		info.reconnect("write", connInfoRev.rev)
	if end {
		return false
	}
	if !rewirte2Tunnel(info, connInfoRev) {
		return false
	}
	return true
}

// packet を connInfoRev に書き込む。
//
// 書き込みに失敗した場合は、 reconnect と再送信を行なう。
// 再送する際は、送信相手の ReadNo との不整合を解決するために、
// 送信済みのデータの再送信も行なう。
// 送信済みのデータの再送信を行なう場合、 writeNo の直前までのデータを再送する。
// writeNo 以降のデータは、 packet のデータを使用して送信する。
// @param info pipe情報
// @param packet 送信するデータ
// @param connInfoRev コネクション情報
func packetWriterSub(info *PipeInfo, packet *PackInfo, connInfoRev *ConnInfoRev) bool {

	sessionInfo := connInfoRev.connInfo.SessionInfo
	for {
		var writeerr error

		if IsDebug() {
			log.Printf(
				"packetWriterSub -- %d, %d",
				sessionInfo.WriteNo, len(packet.bytes))
		}

		if ret, err := writePack(
			packet, connInfoRev.connInfo.Conn, connInfoRev.connInfo, true); err != nil {
			writeerr = err
		} else if !ret {
			return false
		}
		if writeerr != nil {
			log.Printf(
				"tunnel write err log: %p, writeNo=%d, err=%s",
				connInfoRev.connInfo, sessionInfo.WriteNo, writeerr)
			if !reconnectAndRewrite(info, connInfoRev) {
				return false
			}
		} else {
			return true
		}
		log.Printf("retry to write -- %d, %d", sessionInfo.WriteNo, packet.kind)
	}
}

func packetEncrypter(info *PipeInfo) {
	packChan := info.connInfo.SessionInfo.packChan

	ringBufEnc := info.connInfo.SessionInfo.ringBufEnc
	encSyncChan := info.connInfo.SessionInfo.encSyncChan

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
			//buf := make([]byte,BUFSIZE)

			if info.connInfo.CryptCtrlObj != nil {
				packet.bytes = info.connInfo.CryptCtrlObj.enc.Process(
					packet.bytes, buf)
			}
		}

		info.connInfo.SessionInfo.packChanEnc <- packet
	}
}

// write packets to conn
func writePack(packet *PackInfo, stream io.Writer, connInfo *ConnInfo, validPost bool) (bool, error) {
	var writeErr error
	sessionId := connInfo.SessionInfo.SessionId

	switch packet.kind {
	case PACKET_KIND_EOS:
		log.Debug().Int("sessionId", sessionId).Msgf("eos")
		return false, nil
	case PACKET_KIND_SYNC:
		writeErr = WriteSimpleKind(stream, PACKET_KIND_SYNC, packet.citiId, packet.bytes)
		log.Debug().Int("sessionId", sessionId).Msgf("sync sent")
	case PACKET_KIND_NORMAL:
		writeErr = connInfo.writeData(stream, packet.citiId, packet.bytes)
	case PACKET_KIND_NORMAL_DIRECT:
		writeErr = connInfo.writeDataDirect(stream, packet.citiId, packet.bytes)
	case PACKET_KIND_DUMMY:
		writeErr = WriteDummy(stream)
		validPost = false
	default:
		log.Fatal().Msgf("illegal kind: %d", packet.kind)
	}

	if validPost && writeErr == nil {
		connInfo.SessionInfo.postWriteData(packet)
	}
	return true, writeErr
}

// packChan => conn
func packetWriter(role string, pipeInfo *PipeInfo) {
	sessionInfo := pipeInfo.connInfo.SessionInfo
	sessionId := sessionInfo.SessionId
	packetChan := sessionInfo.packChan
	if PRE_ENC {
		packetChan = sessionInfo.packChanEnc
	}

	var connInfoRev ConnInfoRev
	connInfoRev.rev, connInfoRev.connInfo = pipeInfo.getConn()

	var buffer bytes.Buffer

	packetNo := 0
	for {
		sessionInfo.writeState = 10
		packetNo++

		packetChanWaitingTimeStart := time.Now()
		packet := <-packetChan
		span := time.Now().Sub(packetChanWaitingTimeStart)
		if span > 500*time.Microsecond {
			sessionInfo.packetWriterWaitTime += span
			if span > 5*time.Millisecond {
				log.Debug().Str("role", role).Int("sessionId", sessionId).Msgf("%d - wait packetChan(%v) for %s", packetNo, packetChan, span)
			}
		}
		sessionInfo.writeState = 20

		buffer.Reset()

		end := false // for break outer loop, set when error sending buffer
		for len(packetChan) > 0 && packet.kind == PACKET_KIND_NORMAL {
			// packets are buffered, sent in batch
			if buffer.Len()+len(packet.bytes) > MAX_PACKET_SIZE { // can hold more, have to send now
				break
			}

			if cont, err := writePack(&PackInfo{packet.bytes, PACKET_KIND_NORMAL_DIRECT, packet.citiId}, &buffer, connInfoRev.connInfo, true); err != nil {
				log.Fatal().Str("role", role).Int("sessionId", sessionId).Err(err).Msgf("fail to write to conn")
			} else if !cont {
				end = true
				break
			}

			packet = <-packetChan // read more
		}

		if end {
			break
		}

		sessionInfo.writeState = 30

		if buffer.Len() != 0 {
			// If data is set in buffer, write buffer as there is bound data
			if _, err := connInfoRev.connInfo.Conn.Write(buffer.Bytes()); err != nil {
				log.Err(err).Str("role", role).Int("sessionId", sessionId).Msgf("tunnel batch writing failed, writeNo: %d", connInfoRev.connInfo.SessionInfo.WriteNo)

				// Batch buffer is encrypted with the cipher before reconnect, so if sent as is, decryption fails on the receiving side.
				// To avoid that, if batch write fails, recover with rewrite without batch writing.
				if !reconnectAndRewrite(pipeInfo, &connInfoRev) {
					break
				}
			}
		}

		sessionInfo.writeState = 40
		if !packetWriterSub(pipeInfo, &packet, &connInfoRev) {
			break
		}
	}
	log.Info().Str("role", role).Int("sessionId", sessionId).Msg("writing to conn ends")

	pipeInfo.fin <- true
}

func newPipeInfo(connInfo *ConnInfo, citServerFlag bool, reconnect func(sessionInfo *SessionInfo) *ConnInfo) (*PipeInfo, bool) {
	sessionMgr.mutex.get("newPipeInfo")
	defer sessionMgr.mutex.rel()

	sessionInfo := connInfo.SessionInfo
	info, has := sessionMgr.sessionId2pipe[sessionInfo.SessionId]
	if has {
		return info, false
	}

	info = &PipeInfo{
		reconnectFunc: reconnect,
		connInfo:      connInfo,
		fin:           make(chan bool),
		// reconnected:   make(chan bool),
		citServerFlag: citServerFlag,
	}
	sessionMgr.sessionId2pipe[sessionInfo.SessionId] = info
	return info, true
}

func startRelaySession(role string, connInfo *ConnInfo, interval int, citServerFlag bool, reconnect func(sessionInfo *SessionInfo) *ConnInfo) *PipeInfo {
	pipeInfo, isSessionNew := newPipeInfo(connInfo, citServerFlag, reconnect)
	connInfo.SessionInfo.SetState(Session_state_connected)
	sessionId := connInfo.SessionInfo.SessionId
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

	sessionInfo := connInfo.SessionInfo

	// keepalive goroutine
	go func() {
		log.Info().Str("role", role).Msgf("start keepalive routine ...")

		// TODO update this to a better way
		for !pipeInfo.end {
			for sleepTime := 0; sleepTime < interval; sleepTime += KeepaliveSleepMs {
				time.Sleep(KeepaliveSleepMs * time.Millisecond)
				if pipeInfo.end {
					break
				}
			}
			if !pipeInfo.connecting {
				sessionInfo.packChan <- PackInfo{nil, PACKET_KIND_DUMMY, CITIID_CTRL}
			}
		}
		log.Info().Int("sessionId", sessionId).Msgf("keepalive routine exits")
	}()

	return pipeInfo
}

// KeepaliveSleepMs interval for keepalive check
// If this is long, it takes time to wait for relaySession post-processing.
// If it's short, it will be heavy.
const KeepaliveSleepMs = 500

// Relay tunnel stream between transport stream
func relaySession(info *PipeInfo, citi *ConnInTunnelInfo, hostInfo HostInfo) {
	log.Printf("connected and relay session to %s now", hostInfo.String())

	exitChan := make(chan bool)
	sessionInfo := info.connInfo.SessionInfo

	go stream2Tunnel(citi, info, exitChan)
	go tunnel2Stream(sessionInfo, citi, exitChan)

	<-exitChan
	_ = citi.conn.Close()

	<-exitChan

	log.Printf("close citi: sessionId %d, citiId %d, read %d, write %d", sessionInfo.SessionId, citi.citiId, citi.ReadSize, citi.WriteSize)
	log.Printf("close citi: readNo %d, writeNo %d, sourceBytesChan %d", citi.ReadNo, citi.WriteNo, len(citi.sourceBytesChan))
	log.Printf("close citi: session readNo %d, session writeNo %d", sessionInfo.ReadNo, sessionInfo.WriteNo)
	log.Printf("waitTime: stream2Tunnel %s, tunnel2Stream %s, packetWriter %s, packetReader %s",
		citi.waitTimeInfo.stream2Tunnel, citi.waitTimeInfo.tunnel2Stream, sessionInfo.packetWriterWaitTime, citi.waitTimeInfo.packetReader)

	// sessionInfo.packChan <- PackInfo { nil, PACKET_KIND_EOS, CITIID_CTRL } // pending
}

// 再接続情報
type ReconnectInfo struct {
	// 再接続後のコネクション情報
	Conn *ConnInfo
	// エラー時、再接続の処理を継続するかどうか。継続する場合 true。
	Cont bool
	// 再接続でエラーした際のエラー
	Err error
}

// 再接続をリトライする関数を返す
func CreateToReconnectFunc(reconnect func(sessionInfo *SessionInfo) ReconnectInfo) func(sessionInfo *SessionInfo) *ConnInfo {
	return func(sessionInfo *SessionInfo) *ConnInfo {
		timeList := []time.Duration{
			500 * time.Millisecond,
			1000 * time.Millisecond,
			2000 * time.Millisecond,
			5000 * time.Millisecond,
		}
		index := 0
		sessionId := 0
		if sessionInfo != nil {
			sessionId = sessionInfo.SessionId
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

type ListenInfo struct {
	listener    Listener
	forwardInfo ForwardInfo
}

func (info *ListenInfo) Close() {
	info.listener.Close()
}

type ListenGroup struct {
	list []ListenInfo
}

func (group *ListenGroup) Close() {
	for _, info := range group.list {
		info.Close()
	}
}

func NewListen(isClient bool, forwardList []ForwardInfo) (*ListenGroup, []ForwardInfo) {
	return NewListenWithMaker(isClient, forwardList, func(dst string) (Listener, error) {
		listen, err := net.Listen("tcp", dst)
		if err != nil {
			return nil, err
		}
		return &NetListener{listen}, nil
	})
}

func NewListenWithMaker(isClient bool, forwardList []ForwardInfo, listenMaker func(dst string) (Listener, error)) (*ListenGroup, []ForwardInfo) {
	group := ListenGroup{[]ListenInfo{}}
	var localForwards []ForwardInfo

	for _, forwardInfo := range forwardList {
		if (isClient && !forwardInfo.IsReverseTunnel) || (!isClient && forwardInfo.IsReverseTunnel) {
			local, err := listenMaker(forwardInfo.Src.String())
			if err != nil {
				log.Fatal().Err(err)
				return nil, []ForwardInfo{}
			}
			group.list = append(group.list, ListenInfo{local, forwardInfo})
			log.Printf("%s added to listener group", forwardInfo.String())
		} else {
			localForwards = append(localForwards, forwardInfo)
			log.Printf("%s added to local forwards", forwardInfo.String())
		}
	}

	return &group, localForwards
}

func ListenNewConnectSub(role string, listenInfo ListenInfo, pipeInfo *PipeInfo) {
	sessionId := pipeInfo.connInfo.SessionInfo.SessionId

	process := func() {
		log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("listening connections at %s ... (targeting %s)",
			listenInfo.forwardInfo.Src.String(), listenInfo.forwardInfo.Dst.String())
		src, err := listenInfo.listener.Accept()
		if err != nil {
			log.Fatal().Err(err)
		}
		needClose := true
		defer func() {
			if needClose {
				_ = src.Close()
			}
		}()

		log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("new connection accepted")

		citi := pipeInfo.connInfo.SessionInfo.addCiti(role, src, CITIID_CTRL)
		dst := listenInfo.forwardInfo.Dst

		connInfo := pipeInfo.connInfo

		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_HEADER})
		buf, _ := json.Marshal(&ConnHeader{dst, citi.citiId})
		buffer.Write(buf)
		connInfo.SessionInfo.packChan <- PackInfo{buffer.Bytes(), PACKET_KIND_NORMAL, CITIID_CTRL}
		log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("ctrl header sent to packetChan(%v), wait for response ...", connInfo.SessionInfo.packChan)

		respHeader := <-citi.respHeader
		if respHeader.Result {
			go relaySession(pipeInfo, citi, dst)
			needClose = false
		} else {
			log.Error().Str("role", role).Int("sessionId", sessionId).Msgf("failed to connect %s:%s", dst.String(), respHeader.Mess)
		}
	}

	for {
		process()
	}
}

// ListenAndNewConnect waits for a session to pass through Tunnel & connect to the communication destination of the session
// @param connInfo Tunnel
// @param port Listening port number
// @param parm tunnel information
// @param reconnect reconnection function
func ListenAndNewConnect(isClient bool, listenGroup *ListenGroup, localForwardList []ForwardInfo, connInfo *ConnInfo, param *TunnelParam, reconnect func(sessionInfo *SessionInfo) *ConnInfo) {
	ListenAndNewConnectWithDialer(isClient, listenGroup, localForwardList, connInfo, param, reconnect, func(dst string) (io.ReadWriteCloser, error) {
		log.Info().Msgf("dial %s", dst)
		return net.Dial("tcp", dst)
	})
}

func ListenAndNewConnectWithDialer(isClient bool, listenGroup *ListenGroup, localForwards []ForwardInfo, connInfo *ConnInfo, param *TunnelParam, reconnect func(sessionInfo *SessionInfo) *ConnInfo, dialer func(dst string) (io.ReadWriteCloser, error)) {
	role := "server"
	if isClient {
		role = "client"
	}

	info := startRelaySession(role, connInfo, param.KeepAliveInterval, len(listenGroup.list) > 0, reconnect)

	for _, listenInfo := range listenGroup.list {
		go ListenNewConnectSub(role, listenInfo, info) // start each listening in the listenerGroup
	}

	log.Debug().Str("role", role).Msgf("local forwards: %v", localForwards)
	if len(localForwards) > 0 {
		for {
			header := connInfo.SessionInfo.getHeader()
			if header == nil {
				break
			}
			go establishNewConnection(role, dialer, header, info)
		}
		log.Debug().Str("role", role).Msgf("local forwards ended")
	}
	log.Debug().Str("role", role).Msgf("listener group: %v", listenGroup.list)
	if len(listenGroup.list) > 0 {
		for {
			log.Debug().Str("role", role).Msgf("wait releaseChan")
			if !<-connInfo.SessionInfo.releaseChan {
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
	connInfo.SessionInfo.SetState(Session_state_disconnected)
}

// establishNewConnection initiate a new tcp connection
func establishNewConnection(role string, dialer func(dst string) (io.ReadWriteCloser, error), header *ConnHeader, info *PipeInfo) {
	destAddr := header.HostInfo.String()
	destConn, err := dialer(destAddr)

	sessionInfo := info.connInfo.SessionInfo
	sessionId := sessionInfo.SessionId
	citi := sessionInfo.addCiti(role, destConn, header.CitiId)

	{
		// send CTRL_RESP_HEADER header
		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_RESP_HEADER})
		resp := CtrlRespHeader{err == nil, fmt.Sprint(err), header.CitiId}
		buf, _ := json.Marshal(&resp)
		buffer.Write(buf)
		sessionInfo.packChan <- PackInfo{buffer.Bytes(), PACKET_KIND_NORMAL, CITIID_CTRL}
		log.Info().Str("role", role).Int("sessionId", sessionId).Msg("ctrl resp header pushed into packetChan")

		if err != nil { // note this is the dialing error
			log.Err(err).Str("role", role).Int("sessionId", sessionId).Msgf("fail to dial %s", destAddr)
			return
		}
	}
	defer func() { _ = destConn.Close() }()
	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("connected to %s", destAddr)

	relaySession(info, citi, header.HostInfo)
	log.Info().Str("role", role).Int("sessionId", sessionId).Msgf("connection to %s closed", destAddr)
}

// sends a dummy(nil) header to avoid waiting
func reverseTunnelPreCloseHook(info *PipeInfo) {
	sessionInfo := info.connInfo.SessionInfo

	log.Info().Msgf("sessionId: %d, pre close action, is reverse tunnel: %t", sessionInfo.SessionId, sessionInfo.isTunnelServer)
	if sessionInfo.isTunnelServer {
		for len(sessionInfo.ctrlInfo.waitHeaderCount) > 0 {
			count := len(sessionInfo.ctrlInfo.waitHeaderCount)
			for index := 0; index < count; index++ {
				sessionInfo.ctrlInfo.header <- nil // send a dummy to avoid waiting for connection
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
