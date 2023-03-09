// -*- coding: utf-8 -*-
package main

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

	//"regexp"
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

var verboseFlag = false

func IsVerbose() bool {
	return verboseFlag
}

var debugFlag = false

func IsDebug() bool {
	return debugFlag
}

// combination of tcp to pass over tunnel
type Forward struct {
	Reverse bool     // true if this is a reverse tunnel
	Src     HostInfo // listening host:port
	Dest    HostInfo // forward host:port
}

func (info *Forward) String() string {
	return fmt.Sprintf("Forward(reverse=%t, %s => %s)", info.Reverse, info.Src.String(), info.Dest.String())
}

// tunnel control parameters
type TunnelParam struct {
	// common password for session authentication
	pass *string
	// session mode
	Mode string
	// Connectable IP patterns.
	// If nil, no IP restrictions.
	maskedIP *MaskIP
	// Password to encrypt session communication
	encPass *string
	// The communication number to encrypt the communication of the session.
	// -1: always encrypted
	// 0: no encryption
	// N: Encrypt the remaining N communications
	encCount int
	// Interval between connection checks to avoid idleness (ms)
	keepAliveInterval int
	// magic
	magic []byte
	// CTRL_*
	ctrl int
	// server information
	serverInfo HostInfo
	// Information to add to websocket request headers
	wsReqHeader http.Header
}

// when reconnecting the session,
// number of packets to keep data for retransmission
const PACKET_NUM_BASE = 30
const PACKET_NUM_DIV = 2
const PACKET_NUM = (PACKET_NUM_DIV * PACKET_NUM_BASE)

// maximum size to combine writes
const MAX_PACKET_SIZE = 10 * 1024

const CITIID_CTRL = 0
const CITIID_USR = 1

const CTRL_HEADER = 0
const CTRL_RESP_HEADER = 1

// Can't be true until CryptCtrlObj after reconnection can be used again
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

func (ch ConnHeader) String() string {
	return fmt.Sprintf("ConnectControl(host: %s, stream: %d)", ch.HostInfo.String(), ch.CitiId)
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
	conn         io.ReadWriteCloser
	citiId       uint32
	readPackChan chan []byte
	end          bool

	// channel for flow control
	syncChan chan bool

	// to hold packets resent to WritePackList,
	// Keep packet buffers in the link.
	// Buffer for write.
	ringBufW *RingBuf
	// Buffer for Read.
	ringBufR *RingBuf

	// number of packets read in this session
	ReadNo int64
	// number of packets written in this session
	WriteNo   int64
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

// session information
type SessionInfo struct {
	// ID that identifies the session
	SessionId    int
	SessionToken string

	// channel for packet writing
	packChan    chan PackInfo
	packChanEnc chan PackInfo

	// size read from pipe
	readSize int64
	// size written to pipe
	wroteSize int64

	citiId2Info map[uint32]*ConnInTunnelInfo
	nextCtitId  uint32

	// number of packets read in this session
	ReadNo int64
	// number of packets written in this session
	WriteNo int64

	// List of SessionPackets sent.
	// Retain SessionPackets for the latest PACKET_NUM.
	WritePackList *list.List

	// Packet number to resend.
	// -1 means no resending.
	ReWriteNo int64

	ctrlInfo CtrlInfo

	state string

	isTunnelServer bool

	ringBufEnc  *RingBuf
	encSyncChan chan bool

	packetWriterWaitTime time.Duration

	readState  int
	writeState int

	// Waiting for reconnet.
	// 0: no wait, 1: wait for either read or write, 2: wait for both read/write
	reconnetWaitState int

	releaseChan chan bool

	// mutex for member access exclusion of this structure
	mutex *Lock
}

func (sessionInfo *SessionInfo) GetPacketBuf(citiId uint32, packSize uint16) []byte {
	if citiId >= CITIID_USR {
		if citi := sessionInfo.getCiti(citiId); citi != nil {
			buf := citi.ringBufR.getCur()
			if len(buf) < int(packSize) {
				log.Fatal().Msgf("illegal packet size: %d", len(buf))
			}
			return buf[:packSize]
		}
	}
	return make([]byte, packSize)
}

func (sessionInfo *SessionInfo) SetState(state string) {
	sessionInfo.state = state
}

func (sessionInfo *SessionInfo) Setup() {
	for count := uint32(0); count < CITIID_USR; count++ {
		sessionInfo.citiId2Info[count] = NewConnInTunnelInfo(nil, count)
	}

	sessionInfo.ctrlInfo.waitHeaderCount = make(chan int, 100)
	sessionInfo.ctrlInfo.header = make(chan *ConnHeader, 1)
	//sessionInfo.ctrlInfo.respHeader = make(chan *CtrlRespHeader,1)

	for count := 0; count < PACKET_NUM_DIV; count++ {
		sessionInfo.encSyncChan <- true
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
		fmt.Fprintf(stream, "releaseChan: %d\n", len(sessionInfo.releaseChan))
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
				stream, "syncChan: %d, readPackChan %d, readNo %d, writeNo %d\n",
				len(citi.syncChan), len(citi.readPackChan), citi.ReadNo, citi.WriteNo)
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

func (sessionInfo *SessionInfo) UpdateSessionId(sessionId int, token string) {
	sessionMgr.mutex.get("UpdateSessionId")
	defer sessionMgr.mutex.rel()

	sessionInfo.SessionId = sessionId
	sessionInfo.SessionToken = token
	sessionMgr.sessionToken2info[sessionInfo.SessionToken] = sessionInfo
}

func NewConnInTunnelInfo(conn io.ReadWriteCloser, citiId uint32) *ConnInTunnelInfo {
	citi := &ConnInTunnelInfo{
		conn:         conn,
		citiId:       citiId,
		readPackChan: make(chan []byte, PACKET_NUM),
		end:          false,
		syncChan:     make(chan bool, PACKET_NUM_DIV),
		ringBufW:     NewRingBuf(PACKET_NUM, BUFSIZE),
		ringBufR:     NewRingBuf(PACKET_NUM, BUFSIZE),
		ReadNo:       0,
		WriteNo:      0,
		ReadSize:     0,
		WriteSize:    0,
		respHeader:   make(chan *CtrlRespHeader),
		ReadState:    0,
		WriteState:   0,
		waitTimeInfo: WaitTimeInfo{},
	}
	for count := 0; count < PACKET_NUM_DIV; count++ {
		citi.syncChan <- true
	}
	return citi
}

func (sessionInfo *SessionInfo) getHeader() *ConnHeader {
	ctrlInfo := sessionInfo.ctrlInfo
	ctrlInfo.waitHeaderCount <- 0

	header := <-ctrlInfo.header

	<-ctrlInfo.waitHeaderCount

	return header
}

func (info *SessionInfo) addCiti(conn io.ReadWriteCloser, citiId uint32) *ConnInTunnelInfo {
	sessionMgr.mutex.get("addCiti")
	defer sessionMgr.mutex.rel()

	if citiId == CITIID_CTRL {
		citiId = info.nextCtitId
		info.nextCtitId++
		if info.nextCtitId <= CITIID_USR {
			log.Fatal().Msg("info.nextCtitId is overflow")
		}
	}

	citi, has := info.citiId2Info[citiId]
	if has {
		log.Printf("has Citi -- %d %d", info.SessionId, citiId)
		return citi
	}
	citi = NewConnInTunnelInfo(conn, citiId)
	info.citiId2Info[citiId] = citi
	log.Printf("addCiti -- %d %d %d", info.SessionId, citiId, len(info.citiId2Info))
	return citi
}

func (info *SessionInfo) getCiti(citiId uint32) *ConnInTunnelInfo {
	sessionMgr.mutex.get("getCiti")
	defer sessionMgr.mutex.rel()

	if citi, has := info.citiId2Info[citiId]; has {
		return citi
	}
	return nil
}

func (info *SessionInfo) delCiti(citi *ConnInTunnelInfo) {
	sessionMgr.mutex.get("delCiti")
	defer sessionMgr.mutex.rel()

	delete(info.citiId2Info, citi.citiId)

	log.Printf(
		"delCiti -- %d %d %d", info.SessionId, citi.citiId, len(info.citiId2Info))

	// discard stuffed data
	log.Printf("delCiti discard readPackChan -- %d", len(citi.readPackChan))
	for len(citi.readPackChan) > 0 {
		<-citi.readPackChan
	}
}

func (info *SessionInfo) hasCiti() bool {
	sessionMgr.mutex.get("hasCiti")
	defer sessionMgr.mutex.rel()

	log.Printf("hasCiti -- %d %d", info.SessionId, len(info.citiId2Info))

	return len(info.citiId2Info) > CITIID_USR
}

// connection information
type ConnInfo struct {
	// connection
	Conn io.ReadWriteCloser
	// encryption information
	CryptCtrlObj *CryptCtrl
	// session information
	SessionInfo *SessionInfo
	writeBuffer bytes.Buffer
}

// Generate ConnInfo
//
// @param conn connection
// @param pass encrypted password
// @param count encryption count
// @param sessionInfo session information
// @returnConnInfo
func CreateConnInfo(
	conn io.ReadWriteCloser, pass *string, count int,
	sessionInfo *SessionInfo, isTunnelServer bool) *ConnInfo {
	if sessionInfo == nil {
		sessionInfo = newEmptySessionInfo(0, "", isTunnelServer)
	}
	return &ConnInfo{
		conn, CreateCryptCtrl(pass, count), sessionInfo, bytes.Buffer{}}
}

// send resent packet number
//
// @param readNo Read packet number of connection destination
func (sessionInfo *SessionInfo) SetReWrite(readNo int64) {
	if sessionInfo.WriteNo > readNo {
		// If the number of packets received by the other party is less than the number of packets we sent,
		// resend the packet.
		sessionInfo.ReWriteNo = readNo
	} else if sessionInfo.WriteNo == readNo {
		// If the number of packets we sent matches the number of packets received by the other party,
		// no resend.
		sessionInfo.ReWriteNo = -1
	} else {
		// If the number of packets received by the other party is more than the number of packets we sent,
		// error because that's not possible
		log.Fatal().Msg("mismatch WriteNo")
	}
}

// session management
type sessionManager struct {
	// map of sessionID -> SessionInfo
	sessionToken2info map[string]*SessionInfo
	// map of sessionID -> ConnInfo
	sessionId2conn map[int]*ConnInfo
	// map of sessionID -> pipeInfo
	sessionId2pipe map[int]*pipeInfo
	// A map to determine if sessions on the connection are enabled.
	// I feel like it could be smarter to use channel. .
	conn2alive map[io.ReadWriteCloser]bool
	// mutex when accessing values in sessionManager
	mutex Lock
}

var sessionMgr = sessionManager{
	map[string]*SessionInfo{},
	map[int]*ConnInfo{},
	map[int]*pipeInfo{},
	map[io.ReadWriteCloser]bool{},
	Lock{}}

// Register the specified connection in session management
func SetSessionConn(connInfo *ConnInfo) {
	sessionId := connInfo.SessionInfo.SessionId
	log.Print("SetSessionConn: sessionId -- ", sessionId)
	sessionMgr.mutex.get("SetSessionConn")
	defer sessionMgr.mutex.rel()

	sessionMgr.sessionId2conn[connInfo.SessionInfo.SessionId] = connInfo
	sessionMgr.conn2alive[connInfo.Conn] = true
}

// Get SessionInfo associated with the specified session token
func GetSessionInfo(token string) (*SessionInfo, bool) {
	sessionMgr.mutex.get("GetSessionInfo")
	defer sessionMgr.mutex.rel()

	sessionInfo, has := sessionMgr.sessionToken2info[token]
	return sessionInfo, has
}

// wait for communication of the specified connection to end
func JoinUntilToCloseConn(conn io.ReadWriteCloser) {
	log.Printf("join start -- %v\n", conn)

	isAlive := func() bool {
		sessionMgr.mutex.get("JoinUntilToCloseConn")
		defer sessionMgr.mutex.rel()

		if alive, has := sessionMgr.conn2alive[conn]; has && alive {
			return true
		}
		return false
	}

	for {
		if !isAlive() {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("join end -- %v\n", conn)
}

// pipe information.
//
// Control information that relays communication between tunnel and connection destination
type pipeInfo struct {
	// Revision of connInfo. Counts up each time reconnection is established.
	rev int
	// reconnect function
	//
	// @param sessionInfo session information
	// @return *ConnInfo Connected connection.
	// nil if unable to reconnect.
	// Retry reconnection in this function.
	// If this function returns nil, give up reconnection.
	reconnectFunc func(sessionInfo *SessionInfo) *ConnInfo
	// true when this Tunnel connection should be terminated
	end bool
	// // Channel for waiting for the end of relay processing
	// fin chan bool
	// true while reconnecting
	connecting bool
	// Connection information connecting pipe
	connInfo    *ConnInfo
	fin         chan bool
	reconnected chan bool

	// true if citi is server
	citServerFlag bool
}

func (info *pipeInfo) sendRelease() {
	if info.citServerFlag {
		releaseChan := info.connInfo.SessionInfo.releaseChan
		if len(releaseChan) == 0 {
			releaseChan <- true
		}
	}
}

type PackInfo struct {
	// write data
	bytes []byte
	// PACKET_KIND_*
	kind   int8
	citiId uint32
}

// hold the data written in the session
type SessionPacket struct {
	// packet number
	no   int64
	pack PackInfo
}

func (sessionInfo *SessionInfo) postWriteData(packInfo *PackInfo) {
	list := sessionInfo.WritePackList
	list.PushBack(SessionPacket{no: sessionInfo.WriteNo, pack: *packInfo})
	if list.Len() > PACKET_NUM {
		list.Remove(list.Front())
	}
	if PRE_ENC {
		if (sessionInfo.WriteNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 {
			sessionInfo.encSyncChan <- true
		}
	}
	sessionInfo.WriteNo++
	sessionInfo.wroteSize += int64(len(packInfo.bytes))
}

// write data to connection
//
// Here, save the written data in WritePackList.
//
// @param info connection
// @param bytes write data
// @return error on failure error
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

// read data from connection
//
// @param info connection
// @param work work buffer
// @return error on failure error
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
			if IsDebug() {
				log.Printf("get sync -- %d", packNo)
			}
			// When the other party receives it, update syncChan and set it so that the sending process can proceed
			if citi := info.SessionInfo.getCiti(item.citiId); citi != nil {
				citi.syncChan <- true
			} else {
				log.Print("readData discard -- ", item.citiId)
			}
		default:
			// Skip.
			//log.Print( "skip kind -- ", kind )
		}
	}
	info.SessionInfo.readSize += int64(len(item.buf))
	return item, nil
}

// reconnect
//
// @param rev current revision
// @return ConnInfo Connection after reconnection
// @return int Revision after reconnection
// @return bool Whether to terminate the session. true to terminate
func (info *pipeInfo) reconnect(txt string, rev int) (*ConnInfo, int, bool) {

	workRev, workConnInfo := info.getConn()
	sessionInfo := info.connInfo.SessionInfo

	sessionInfo.mutex.get("reconnect")
	sessionInfo.reconnetWaitState++
	sessionInfo.mutex.rel()

	log.Printf("reconnect -- rev: %s, %d %d, %p", txt, rev, workRev, workConnInfo)

	reqConnect := false

	sub := func() bool {
		sessionInfo.mutex.get("reconnect-sub")
		defer sessionInfo.mutex.rel()

		if info.rev != rev {
			if !info.connecting {
				sessionInfo.reconnetWaitState--
				workRev = info.rev
				workConnInfo = info.connInfo
				return true
			}
		} else {
			info.connecting = true
			info.rev++
			reqConnect = true
			return true
		}
		return false
	}

	if info.reconnectFunc != nil {
		for {
			if sub() {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}
	} else {
		reqConnect = true
		info.rev++
	}

	if reqConnect {
		releaseSessionConn(info)
		prepareClose(info)

		if len(sessionInfo.packChan) == 0 {
			// Don't let packetWriter stop waiting for sessionInfo.packChan
			// Throw dummy.
			sessionInfo.packChan <- PackInfo{nil, PACKET_KIND_DUMMY, CITIID_CTRL}
		}

		if !info.end {
			sessionInfo.SetState(Session_state_reconnecting)

			workRev = info.rev
			workInfo := info.reconnectFunc(sessionInfo)
			if workInfo != nil {
				info.connInfo = workInfo
				log.Printf("new connInfo -- %p", workInfo)
				sessionInfo.SetState(Session_state_connected)
			} else {
				info.end = true
				info.connInfo = CreateConnInfo(
					dummyConn, nil, 0, sessionInfo, sessionInfo.isTunnelServer)
				log.Printf("set dummyConn")
			}
			workConnInfo = info.connInfo

			func() {
				sessionInfo.mutex.get("reconnectFunc-end")
				defer sessionInfo.mutex.rel()
				sessionInfo.reconnetWaitState--
			}()

			info.connecting = false
		}
	}

	log.Printf(
		"connected: [%s] rev -- %d, end -- %v, %p",
		txt, workRev, info.end, workConnInfo)
	return workConnInfo, workRev, info.end
}

// release session connection
func releaseSessionConn(info *pipeInfo) {
	connInfo := info.connInfo
	log.Printf("releaseSessionConn -- %d", connInfo.SessionInfo.SessionId)
	sessionMgr.mutex.get("releaseSessionConn")
	defer sessionMgr.mutex.rel()

	delete(sessionMgr.conn2alive, connInfo.Conn)
	delete(sessionMgr.sessionId2conn, connInfo.SessionInfo.SessionId)

	connInfo.Conn.Close()

	info.sendRelease()
}

// get the connection corresponding to the specified session
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
		// log.Print( "GetSessionConn ng ... session: ", sessionId )
		// return nil
		// }

		time.Sleep(500 * time.Millisecond)
	}
}

// get the connection corresponding to the specified session
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

// get connection information
//
// @return int revision information
// @return *ConnInfo connection information
func (info *pipeInfo) getConn() (int, *ConnInfo) {
	sessionInfo := info.connInfo.SessionInfo
	sessionInfo.mutex.get("getConn")
	defer sessionInfo.mutex.rel()

	return info.rev, info.connInfo
}

// Handle Tunnel -> dst pipe.
//
// After processing, write data to info.fin.
//
// @param info pipe info
// @param dst destination
func tunnel2Stream(sessionInfo *SessionInfo, dst *ConnInTunnelInfo, fin chan bool) {

	for {
		dst.ReadState = 10
		prev := time.Now()
		readBuf := <-dst.readPackChan
		dst.ReadState = 20
		span := time.Now().Sub(prev)
		dst.waitTimeInfo.tunnel2Stream += span
		if IsVerbose() && span > 5*time.Millisecond {
			log.Printf("tunnel2Stream -- %d, %s", dst.ReadNo, span)
		}
		readSize := len(readBuf)

		if IsDebug() {
			log.Printf("tunnel2Stream -- %d, %s", dst.ReadNo, readSize)
		}

		if (dst.ReadNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 {
			// Return SYNC after reading a certain number
			var buffer bytes.Buffer
			binary.Write(&buffer, binary.BigEndian, dst.ReadNo)
			dst.ReadState = 30
			if IsDebug() {
				log.Printf("put sync")
			}
			sessionInfo.packChan <- PackInfo{buffer.Bytes(), PACKET_KIND_SYNC, dst.citiId}
		}
		dst.ReadNo++
		dst.ReadSize += int64(len(readBuf))

		if readSize == 0 {
			log.Printf("tunnel2Stream: read 0 end -- %d", len(sessionInfo.packChan))
			break
		}
		dst.ReadState = 40
		_, writeerr := dst.conn.Write(readBuf)
		dst.ReadState = 50
		if writeerr != nil {
			log.Printf("write err log: ReadNo=%d, err=%s", dst.ReadNo, writeerr)
			break
		}
	}

	// Remove data from dst.readPackChan to prevent stuffing
	sessionInfo.delCiti(dst)
	fin <- true
}

// resend data to Tunnel
//
// @param info pipe info
// @param connInfo connection information
// @param rev revision
// @return bool true to continue processing
func rewrite2Tunnel(info *pipeInfo, connInfoRev *ConnInfoRev) bool {
	// resend packets after reconnection
	sessionInfo := connInfoRev.connInfo.SessionInfo
	if sessionInfo.ReWriteNo == -1 {
		return true
	}
	log.Printf(
		"rewrite2Tunnel: %d, %d", sessionInfo.WriteNo, sessionInfo.ReWriteNo)
	for sessionInfo.WriteNo > sessionInfo.ReWriteNo {
		item := sessionInfo.WritePackList.Front()
		for ; item != nil; item = item.Next() {
			packet := item.Value.(SessionPacket)
			if packet.no == sessionInfo.ReWriteNo {
				// The packet to be resent was found
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

// Do relay processing for src -> tunnel communication
//
// @param src source
// @param info pipe info
func stream2Tunnel(src *ConnInTunnelInfo, info *pipeInfo, fin chan bool) {
	_, connInfo := info.getConn()
	session := connInfo.SessionInfo
	packChan := session.packChan

	for {
		src.WriteState = 10
		if (src.WriteNo % PACKET_NUM_BASE) == 0 {
			// In order to leave a buffer for retransmission when reconnecting after tunnel disconnection, get syncChan
			// for every PACKET_NUM_BASE
			// Don't send too much when the other party hasn't received it.
			prev := time.Now()
			<-src.syncChan
			span := time.Now().Sub(prev)
			src.waitTimeInfo.stream2Tunnel += span
			if span >= 5*time.Millisecond {
				log.Debug().Msgf("sync packet takes %s, writeNo: %d", span, src.WriteNo)
			}
			log.Printf("got sync packet from syncChan")
		}
		src.WriteNo++

		src.WriteState = 20
		buf := src.ringBufW.getNext() // switch buffer
		log.Debug().Msgf("got new buf from write ringBuffer, %p", buf)
		readSize, readErr := src.conn.Read(buf)

		src.WriteState = 30
		log.Debug().Msgf("writeNo: %d, readSize: %d", src.WriteNo, readSize)
		if readErr != nil {
			packChan <- PackInfo{make([]byte, 0), PACKET_KIND_NORMAL, src.citiId} // write 0 bytes data to the destination when the source is dead
			log.Error().Msgf("fail to read into write ringBuffer, err: %v", readErr)
			break
		}
		if readSize == 0 {
			log.Warn().Msgf("ignore 0-size packet")
			continue
		}
		src.WriteSize += int64(readSize)

		src.WriteState = 40
		if (src.WriteNo%PACKET_NUM_BASE) == 0 && len(src.syncChan) == 0 {
			log.Info().Msgf("packet group ends, wait for sync packet ...")
			work := <-src.syncChan // If it's the last packet in the packet group and no SYNC is coming, wait for SYNC before sending.
			src.syncChan <- work   // We read ahead SYNC, so we write back SYNC.
			log.Info().Msgf("sync packet pushed")
		}

		src.WriteState = 50
		packChan <- PackInfo{buf[:readSize], PACKET_KIND_NORMAL, src.citiId}
		log.Info().Msgf("buffer packet pushed to packetChan")
	}
	fin <- true
}

type ConnInfoRev struct {
	connInfo *ConnInfo
	rev      int
}

func bin2Ctrl(sessionInfo *SessionInfo, buf []byte) {
	if len(buf) == 0 {
		log.Print("bin2Ctrl 0")
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
			log.Fatal().Msgf("failed to read header: %v", err)
		}
		log.Print("header ", header)
		sessionInfo.ctrlInfo.header <- &header
	case CTRL_RESP_HEADER:
		resp := CtrlRespHeader{}
		if err := json.NewDecoder(&buffer).Decode(&resp); err != nil {
			log.Fatal().Msgf("failed to read header: %v", err)
		}
		log.Print("resp ", resp)
		if citi := sessionInfo.getCiti(resp.CitiId); citi != nil {
			citi.respHeader <- &resp
		} else {
			log.Print("bin2Ctrl discard -- ", resp.CitiId)
		}
	}
}

func packetReader(info *pipeInfo) {
	rev, connInfo := info.getConn()
	sessionInfo := connInfo.SessionInfo

	buf := make([]byte, BUFSIZE)
	for {
		readSize := 0
		var citi *ConnInTunnelInfo
		for {
			sessionInfo.readState = 10
			if packet, err := connInfo.readData(buf); err != nil {
				sessionInfo.readState = 20
				log.Printf(
					"tunnel read err log: %p, readNo=%d, err=%s",
					connInfo, sessionInfo.ReadNo, err)
				end := false
				connInfo.Conn.Close()
				connInfo, rev, end = info.reconnect("read", rev)
				if end {
					readSize = 0
					info.end = true
					break
				}
			} else {
				sessionInfo.readState = 30
				if IsDebug() {
					log.Printf(
						"packetReader %d, %d",
						sessionInfo.readState, len(packet.buf))
				}
				if packet.citiId == CITIID_CTRL {
					bin2Ctrl(sessionInfo, packet.buf)
					// Dummy set readSize to 1 so that the process doesn't end
					readSize = 1
				} else {
					if citi = sessionInfo.getCiti(packet.citiId); citi != nil {
						// packet.buf to citi.readPackChan
						// put in and processed in another thread.
						// On the other hand, packet.buf refers to a fixed address, so
						// If you readData before processing in another thread, the contents of packet.buf
						// will be overwritten.
						// Copy to prevent it.

						// cloneBuf := citi.ringBufR.getNext()[:len(packet.buf)]
						// copy( cloneBuf, packet.buf )
						citi.ringBufR.getNext()
						cloneBuf := packet.buf

						prev := time.Now()
						citi.readPackChan <- cloneBuf
						span := time.Now().Sub(prev)

						citi.waitTimeInfo.packetReader += span
						if IsVerbose() && span >= 5*time.Millisecond {
							log.Printf(
								"packetReader -- %s %s %d",
								span, citi.waitTimeInfo.packetReader, citi.ReadNo)
						}

						readSize = len(cloneBuf)
					} else {
						log.Printf("packetReader discard -- %d", packet.citiId)
						readSize = 1
					}
				}
				if readSize == 0 {
					if packet.citiId == CITIID_CTRL {
						info.end = true
					}
				}
				break
			}
		}
		sessionInfo.readState = 40

		if readSize == 0 {
			if citi != nil && len(citi.syncChan) == 0 {
				// When exiting, stream2Tunnel() may be waiting
				// Notify syncChan here
				citi.syncChan <- true
			}
			sessionInfo.readState = 50
			if info.end {
				info.sendRelease()
				for _, workciti := range sessionInfo.citiId2Info {
					if len(workciti.syncChan) == 0 {
						// When exiting, stream2Tunnel() may be waiting
						// Notify syncChan here
						workciti.syncChan <- true
					}
				}
				log.Print("read 0 end")
				break
			}
		}
	}

	prepareClose(info)

	log.Print("packetReader end -- ", sessionInfo.SessionId)
	info.fin <- true
}

func reconnectAndRewrite(
	info *pipeInfo, connInfoRev *ConnInfoRev) bool {
	end := false
	connInfoRev.connInfo, connInfoRev.rev, end =
		info.reconnect("write", connInfoRev.rev)
	if end {
		return false
	}
	if !rewrite2Tunnel(info, connInfoRev) {
		return false
	}
	return true
}

// Write packet to connInfoRev.
//
// If the write fails, reconnect and resend.
// When resending, to resolve the inconsistency with her ReadNo of the sending party,
// Also resend data that has already been sent.
// When resending data that has already been sent, resend the data up to just before writeNo.
// Send data after writeNo using packet data.
// @param info pipe information
// @param packet data to send
// @param connInfoRev connection information
func packetWriterSub(
	info *pipeInfo, packet *PackInfo, connInfoRev *ConnInfoRev) bool {

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

func packetEncrypter(info *pipeInfo) {
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

// output packet to stream
//
// @param packet packet
// @param stream destination
// @param connInfo connection
// true when calling @param validPost postWriteData processing
// @return bool true to continue sending
// @return error error when sending failed
func writePack(
	packet *PackInfo, stream io.Writer,
	connInfo *ConnInfo, validPost bool) (bool, error) {
	var writeerr error

	switch packet.kind {
	case PACKET_KIND_EOS:
		log.Printf("eos -- sessionId %d", connInfo.SessionInfo.SessionId)
		return false, nil
	case PACKET_KIND_SYNC:
		if IsDebug() {
			log.Printf("write sync")
		}
		writeerr = WriteSimpleKind(stream, PACKET_KIND_SYNC, packet.citiId, packet.bytes)
	case PACKET_KIND_NORMAL:
		writeerr = connInfo.writeData(stream, packet.citiId, packet.bytes)
	case PACKET_KIND_NORMAL_DIRECT:
		writeerr = connInfo.writeDataDirect(stream, packet.citiId, packet.bytes)
	case PACKET_KIND_DUMMY:
		writeerr = WriteDummy(stream)
		validPost = false
	default:
		log.Fatal().Msgf("illegal kind: %d", packet.kind)
	}

	if validPost && writeerr == nil {
		connInfo.SessionInfo.postWriteData(packet)
	}
	return true, writeerr
}

// Packet write function to Tunnel
//
// # Executed by go routine
//
// @param info pipe control information
// channel to receive @param packChan PackInfo
func packetWriter(info *pipeInfo) {

	sessionInfo := info.connInfo.SessionInfo
	packChan := sessionInfo.packChan
	if PRE_ENC {
		packChan = sessionInfo.packChanEnc
	}

	var connInfoRev ConnInfoRev
	connInfoRev.rev, connInfoRev.connInfo = info.getConn()

	var buffer bytes.Buffer

	packetNo := 0
	for {
		sessionInfo.writeState = 10

		packetNo++
		prev := time.Now()
		packet := <-packChan
		span := time.Now().Sub(prev)
		if span > 500*time.Microsecond {
			sessionInfo.packetWriterWaitTime += span
			if IsVerbose() && span > 5*time.Millisecond {
				log.Printf("packetWriterWaitTime -- %d, %s", packetNo, span)
			}
		}

		sessionInfo.writeState = 20

		buffer.Reset()

		end := false
		for len(packChan) > 0 && packet.kind == PACKET_KIND_NORMAL {
			log.Debug().Msgf("buffering packets ...")
			// If there are still write requests, output them to buffer once and combine them for efficiency.

			if buffer.Len()+len(packet.bytes) > MAX_PACKET_SIZE {
				break
			}

			if cont, err := writePack(
				&PackInfo{packet.bytes, PACKET_KIND_NORMAL_DIRECT, packet.citiId},
				&buffer, connInfoRev.connInfo, true); err != nil {
				log.Fatal().Msgf("writePack error: %v", err)
			} else if !cont {
				end = true
				break
			}

			packet = <-packChan
		}
		if end {
			break
		}

		sessionInfo.writeState = 30

		if buffer.Len() != 0 {
			log.Debug().Msgf("packets buffering is done, size: %d, writing to conn ...", buffer.Len())
			// If data is set in buffer,
			// write buffer as there is bound data
			//log.Print( "concat -- ", len( buffer.Bytes() ) )
			if _, err := connInfoRev.connInfo.Conn.Write(buffer.Bytes()); err != nil {
				log.Printf(
					"tunnel batch write err log: %p, writeNo=%d, err=%s",
					connInfoRev.connInfo, connInfoRev.connInfo.SessionInfo.WriteNo, err)
				// Batch buffer is encrypted with the cipher before reconnect, so
				// If sent as is, decryption fails on the receiving side.
				// To avoid that, if batch write fails,
				// Recover with rewrite without batch writing.
				if !reconnectAndRewrite(info, &connInfoRev) {
					break
				}
			}
		}

		sessionInfo.writeState = 40
		if !packetWriterSub(info, &packet, &connInfoRev) {
			break
		}
	}

	log.Print("packetWriter end -- ", sessionInfo.SessionId)
	info.fin <- true

}

func NewPipeInfo(
	connInfo *ConnInfo, citServerFlag bool,
	reconnect func(sessionInfo *SessionInfo) *ConnInfo) (*pipeInfo, bool) {

	sessionMgr.mutex.get("NewPipeInfo")
	defer sessionMgr.mutex.rel()

	sessionInfo := connInfo.SessionInfo

	info, has := sessionMgr.sessionId2pipe[sessionInfo.SessionId]
	if has {
		return info, false
	}

	info = &pipeInfo{
		0, reconnect, false, false, connInfo,
		make(chan bool), make(chan bool), citServerFlag}
	sessionMgr.sessionId2pipe[sessionInfo.SessionId] = info

	return info, true
}

func startRelaySession(connInfo *ConnInfo, interval int, citServerFlag bool, reconnect func(sessionInfo *SessionInfo) *ConnInfo) *pipeInfo {
	mux, isNewMux := NewPipeInfo(connInfo, citServerFlag, reconnect)
	connInfo.SessionInfo.SetState(Session_state_connected)
	if !isNewMux {
		log.Printf("existing mux, no new mux routines, sessionId: %d", connInfo.SessionInfo.SessionId)
		return mux
	}

	go packetWriter(mux)
	go packetReader(mux)
	if PRE_ENC {
		go packetEncrypter(mux)
	}
	go keepalive(mux, connInfo.SessionInfo, interval)

	return mux
}

func keepalive(info *pipeInfo, sessionInfo *SessionInfo, interval int) {
	// Once every 20 seconds to avoid disconnection due to no communication for a certain period of time
	for !info.end {
		for sleepTime := 0; sleepTime < interval; sleepTime += SLEEP_INTERVAL {
			time.Sleep(SLEEP_INTERVAL * time.Millisecond)
			if info.end {
				break
			}
		}
		if !info.connecting {
			sessionInfo.packChan <- PackInfo{nil, PACKET_KIND_DUMMY, CITIID_CTRL}
		}
	}
	log.Printf("end keepalive -- %d", sessionInfo.SessionId)
}

// Interval for keep alive communication to avoid dead communication (ms)
const KEEP_ALIVE_INTERVAL = 20 * 1000

// Interval in milliseconds to check for keep alive time elapsed.
// If this is long, it takes time to wait for relaySession post-processing.
// If it's short, it'll be heavy.
const SLEEP_INTERVAL = 500

// Relay communication between local and tunnel while being tunneled by tunnel
//
// @param connInfo Tunnel connection information
// Connection destination with @param local Tunnel
// @param reconnect reconnection function
func relaySession(mux *pipeInfo, citi *ConnInTunnelInfo, hostInfo HostInfo) {
	log.Print("local connection established")

	fin := make(chan bool)
	sessionInfo := mux.connInfo.SessionInfo

	go stream2Tunnel(citi, mux, fin)
	go tunnel2Stream(sessionInfo, citi, fin)

	<-fin
	_ = citi.conn.Close()
	<-fin

	log.Printf("close citi: sessionId %d, citiId %d, read %d, write %d", sessionInfo.SessionId, citi.citiId, citi.ReadSize, citi.WriteSize)
	log.Printf("close citi: readNo %d, writeNo %d, readPackChan %d", citi.ReadNo, citi.WriteNo, len(citi.readPackChan))
	log.Printf("close citi: session readNo %d, session writeNo %d", sessionInfo.ReadNo, sessionInfo.WriteNo)
	log.Printf("wait time: stream2Tunnel %s, tunnel2Stream %s, packetWriter %s, packetReader %s", citi.waitTimeInfo.stream2Tunnel,
		citi.waitTimeInfo.tunnel2Stream, sessionInfo.packetWriterWaitTime, citi.waitTimeInfo.packetReader)

	// sessionInfo.packChan <- PackInfo { nil, PACKET_KIND_EOS, CITIID_CTRL } // pending
}

// reconnection information
type ReconnectInfo struct {
	// Connection information after reconnection
	Conn *ConnInfo
	// Whether to continue the reconnection process when an error occurs. true to continue;
	Cont bool
	// Error when reconnection error
	Err error
}

// return a function to retry reconnection
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

func (this *NetListener) Accept() (io.ReadWriteCloser, error) {
	return this.listener.Accept()
}
func (this *NetListener) Close() error {
	return this.listener.Close()
}

type Listener interface {
	Accept() (io.ReadWriteCloser, error)
	Close() error
}

type ListenInfo struct {
	listener    Listener
	forwardInfo Forward
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

func NewListen(isClient bool, forwardList []Forward) (*ListenGroup, []Forward) {
	return NewListenWithMaker(
		isClient, forwardList,
		func(dst string) (Listener, error) {
			listen, err := net.Listen("tcp", dst)
			if err != nil {
				return nil, err
			}
			return &NetListener{listen}, nil
		})
}

func NewListenWithMaker(
	isClient bool, forwardList []Forward,
	listenMaker func(dst string) (Listener, error)) (*ListenGroup, []Forward) {
	group := ListenGroup{[]ListenInfo{}}
	localForward := []Forward{}

	for _, forwardInfo := range forwardList {
		if isClient && !forwardInfo.Reverse ||
			!isClient && forwardInfo.Reverse {
			local, err := listenMaker(forwardInfo.Src.String())
			if err != nil {
				log.Fatal().Err(err)
				return nil, []Forward{}
			}
			group.list = append(group.list, ListenInfo{local, forwardInfo})
		} else {
			localForward = append(localForward, forwardInfo)
		}
	}

	return &group, localForward
}

// Wait for a session to pass through Tunnel & connect to the communication destination of the session
//
// @param connInfo Tunnel
// @param port Listening port number
// @param parm tunnel information
// @param reconnect reconnection function
func ListenAndNewConnect(isClient bool, listenGroup *ListenGroup, localForwardList []Forward, connInfo *ConnInfo, param *TunnelParam,
	reconnect func(sessionInfo *SessionInfo) *ConnInfo) {

	ListenAndNewConnectWithDialer(isClient, listenGroup, localForwardList, connInfo, param, reconnect, func(dst string) (io.ReadWriteCloser, error) {
		log.Printf("dial -- %s", dst)
		return net.Dial("tcp", dst)
	})
}

// Listen for sessions to pass over the Tunnel and handle started sessions.
//
// @param connInfo Tunnel
// @param port Listening port number
// @param parm tunnel information
// @param reconnect reconnection function
//func ListenNewConnect(
//	listenGroup *ListenGroup, connInfo *ConnInfo, param *TunnelParam, loop bool,
//	reconnect func(sessionInfo *SessionInfo) *ConnInfo) {
//
//	info := startRelaySession(connInfo, param.keepAliveInterval, true, reconnect)
//
//	for _, listenInfo := range listenGroup.list {
//		go acceptAndProcessInfinitely(listenInfo, info)
//	}
//
//	for {
//		if !<-connInfo.SessionInfo.releaseChan {
//			break
//		}
//		if !loop {
//			break
//		}
//	}
//	log.Printf("disconnected")
//	connInfo.SessionInfo.SetState(Session_state_disconnected)
//}

func NewConnect(
	dialer func(dst string) (io.ReadWriteCloser, error),
	header *ConnHeader, info *pipeInfo) {
	log.Print("header ", header)

	dstAddr := header.HostInfo.String()
	dst, err := dialer(dstAddr)
	log.Print("NewConnect -- %s", dstAddr)

	sessionInfo := info.connInfo.SessionInfo

	citi := sessionInfo.addCiti(dst, header.CitiId)

	// // pending
	// time.Sleep(100 * time.Millisecond)

	var buffer bytes.Buffer
	buffer.Write([]byte{CTRL_RESP_HEADER})
	resp := CtrlRespHeader{err == nil, fmt.Sprint(err), header.CitiId}
	bytes, _ := json.Marshal(&resp)
	buffer.Write(bytes)

	sessionInfo.packChan <- PackInfo{
		buffer.Bytes(), PACKET_KIND_NORMAL, CITIID_CTRL}
	const Session_state_header = "respheader"

	if err != nil {
		log.Print("fained to connected to ", dstAddr)
		return
	}
	defer dst.Close()

	log.Print("connected to ", dstAddr)

	relaySession(info, citi, header.HostInfo)

	log.Print("closed")
}

func prepareClose(info *pipeInfo) {
	sessionInfo := info.connInfo.SessionInfo

	log.Printf("prepareClose -- %s", sessionInfo.isTunnelServer)

	if sessionInfo.isTunnelServer {
		for len(sessionInfo.ctrlInfo.waitHeaderCount) > 0 {
			count := len(sessionInfo.ctrlInfo.waitHeaderCount)
			log.Print("packetReader: put dummy header -- ", count)
			for index := 0; index < count; index++ {
				// send a dummy to avoid waiting for connection
				sessionInfo.ctrlInfo.header <- nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}
