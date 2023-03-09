// -*- coding: utf-8 -*-
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	//"net"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"

	"crypto/aes"
	"crypto/cipher"

	"github.com/rs/zerolog/log"
)

// MAX of 2 bytes.
// Change the processing of WriteItem and ReadItem if you want to make this larger than 65535.
const BUFSIZE = 65535

// Destination information
type HostInfo struct {
	// scheme. http:// etc.
	Scheme string
	// hostname
	Name string
	// port number
	Port int
	// path
	Path string
	// query
	Query string
}

// String representation of connection destination
func (info *HostInfo) String() string {
	work := fmt.Sprintf("%s%s:%d%s", info.Scheme, info.Name, info.Port, info.Path)
	if info.Query != "" {
		work = fmt.Sprintf("%s?%s", work, info.Query)
	}
	return work
}

func hostname2HostInfo(name string) *HostInfo {
	if strings.Index(name, "://") == -1 {
		name = fmt.Sprintf("http://%s", name)
	}
	serverUrl, err := url.Parse(name)
	if err != nil {
		fmt.Printf("%s", err)
		return nil
	}
	hostport := strings.Split(serverUrl.Host, ":")
	if len(hostport) != 2 {
		fmt.Printf("illegal pattern. set 'hoge.com:1234' -- %s", name)
		return nil
	}
	var port int
	port, err2 := strconv.Atoi(hostport[1])
	if err2 != nil {
		fmt.Printf("%s", err2)
		return nil
	}
	return &HostInfo{"", hostport[0], port, serverUrl.Path, serverUrl.RawQuery}
}

// generate key from password
func getKey(pass []byte) []byte {
	sum := sha256.Sum256(pass)
	return sum[:]
}

// encryption mode
type CryptMode struct {
	// Maximum number of encryption attempts.
	// -1: unlimited
	// 0: no encryption
	// N: maximum encryption times N
	countMax int
	// current encryption count
	count int
	// working buffer
	work []byte
	// encryption processing
	stream cipher.Stream
}
type CryptCtrl struct {
	enc CryptMode
	dec CryptMode
}

// create an object for encryption
//
// @param pass password
// @param count Darkening times
func CreateCryptCtrl(pass *string, count int) *CryptCtrl {
	if pass == nil || count == 0 {
		return nil
	}

	bufSize := BUFSIZE
	key := getKey([]byte(*pass))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	iv := make([]byte, aes.BlockSize)
	for index := 0; index < len(iv); index++ {
		iv[index] = byte(index)
	}

	encrypter := cipher.NewCFBEncrypter(block, iv)
	decrypter := cipher.NewCFBDecrypter(block, iv)

	ctrl := CryptCtrl{
		CryptMode{count, 0, make([]byte, bufSize), encrypter},
		CryptMode{count, 0, make([]byte, bufSize), decrypter}}

	return &ctrl
}

func (mode *CryptMode) IsValid() bool {
	if mode == nil || mode.countMax == 0 {
		return false
	}
	return true
}

// Encryption/compound processing
//
// @param inbuf buffer holding data to be processed
// @param outbuf Buffer to store data after processing.
//
// If nil is specified, store the result in work of CryptMode.
//
// Buffer to store data after @return processing.
//
// Returns a slice of outbuf if non-nil is specified for outbuf.
// If nil is specified for outbuf, return a slice of CryptMode's work.
func (mode *CryptMode) Process(inbuf []byte, outbuf []byte) []byte {
	work := outbuf
	if outbuf == nil {
		work = mode.work
	}
	if len(inbuf) > len(work) {
		panic(fmt.Errorf("over length"))
	}
	if mode.countMax == 0 {
		return inbuf
	}
	if mode.countMax > 0 {
		if mode.countMax > mode.count {
			mode.count++
		} else if mode.countMax <= mode.count {
			mode.countMax = 0
			log.Print("crypto is disabled")
		}
	}
	// buf := work[:len(inbuf)]
	// mode.stream.XORKeyStream( buf, inbuf )
	// return buf

	mode.stream.XORKeyStream(work, inbuf)

	return work[:len(inbuf)]
}

// encryption
func (ctrl *CryptCtrl) Encrypt(bytes []byte) []byte {
	return ctrl.enc.Process(bytes, nil)
}

// Composite
func (ctrl *CryptCtrl) Decrypt(bytes []byte) []byte {
	return ctrl.dec.Process(bytes, nil)
}

// normal packet
const PACKET_KIND_NORMAL = 0

// dummy packet to avoid no communication
const PACKET_KIND_DUMMY = 1

// Packet for notifying the end of packetWriter() processing
const PACKET_KIND_EOS = 2

// Packet for synchronizing Tunnel communication
const PACKET_KIND_SYNC = 3
const PACKET_KIND_NORMAL_DIRECT = 4

var dummyKindBuf = []byte{PACKET_KIND_DUMMY}
var normalKindBuf = []byte{PACKET_KIND_NORMAL}
var syncKindBuf = []byte{PACKET_KIND_SYNC}

var PACKET_LEN_HEADER int = 0

func init() {
	var citiId uint32
	PACKET_LEN_HEADER = len(normalKindBuf) + int(unsafe.Sizeof(citiId))
}

func WriteDummy(ostream io.Writer) error {
	if _, err := ostream.Write(dummyKindBuf); err != nil {
		return err
	}
	return nil
}

func WriteSimpleKind(ostream io.Writer, kind int8, citiId uint32, buf []byte) error {

	var kindbuf []byte
	switch kind {
	case PACKET_KIND_SYNC:
		kindbuf = syncKindBuf
	default:
		log.Fatal().Msgf("illegal kind: %d", kind)
	}

	var buffer bytes.Buffer
	buffer.Grow(PACKET_LEN_HEADER + len(buf))

	if _, err := buffer.Write(kindbuf); err != nil {
		return err
	}
	if err := binary.Write(&buffer, binary.BigEndian, citiId); err != nil {
		return err
	}
	if _, err := buffer.Write(buf); err != nil {
		return err
	}

	_, err := buffer.WriteTo(ostream)
	return err
}

// output data
//
// ostream destination
// buf data
// ctrl encryption information
func WriteItem(
	ostream io.Writer, citiId uint32,
	buf []byte, ctrl *CryptCtrl, workBuf *bytes.Buffer) error {
	// If the number of write calls is large, the communication efficiency is poor.
	// Write to buffer first and then output to ostream.
	var buffer *bytes.Buffer = workBuf
	if buffer == nil {
		buffer = &bytes.Buffer{}
	} else {
		buffer.Reset()
	}
	size := uint16(len(buf))
	buffer.Grow(
		len(normalKindBuf) + int(unsafe.Sizeof(citiId)) +
			int(unsafe.Sizeof(size)) + len(buf))

	if err := WriteItemDirect(buffer, citiId, buf, ctrl); err != nil {
		return err
	}

	_, err := buffer.WriteTo(ostream)
	return err
}

// output data
//
// ostream destination
// buf data
// ctrl encryption information
func WriteItemDirect(ostream io.Writer, citiId uint32, buf []byte, ctrl *CryptCtrl) error {
	if _, err := ostream.Write(normalKindBuf); err != nil {
		return err
	}
	if err := binary.Write(ostream, binary.BigEndian, citiId); err != nil {
		return err
	}
	if ctrl != nil {
		buf = ctrl.enc.Process(buf, nil)
	}
	if err := binary.Write(ostream, binary.BigEndian, uint16(len(buf))); err != nil {
		return err
	}
	_, err := ostream.Write(buf)
	return err
}

type PackItem struct {
	citiId uint32
	buf    []byte
	kind   int8
}

func ReadCitiId(istream io.Reader) (uint32, error) {
	buf := make([]byte, 4)
	_, error := io.ReadFull(istream, buf)
	if error != nil {
		return 0, error
	}
	return binary.BigEndian.Uint32(buf), nil
}

func ReadPackNo(istream io.Reader, kind int8) (*PackItem, error) {
	var item PackItem
	item.kind = kind
	var error error
	if item.citiId, error = ReadCitiId(istream); error != nil {
		return nil, error
	}
	var packNo int64
	item.buf = make([]byte, unsafe.Sizeof(packNo))
	_, err := io.ReadFull(istream, item.buf)
	if err != nil {
		return &item, err
	}
	return &item, nil
}

type CitiBuf interface {
	// get buffer for citiId
	GetPacketBuf(citiId uint32, packSize uint16) []byte
}

type HeapCitiBuf struct {
}

var heapCitiBuf *HeapCitiBuf = &HeapCitiBuf{}

func (citiBuf *HeapCitiBuf) GetPacketBuf(citiId uint32, packSize uint16) []byte {
	return make([]byte, packSize)
}

// load the data
//
// @param istream source stream
// @param ctrl encryption control
// @param workBuf
func ReadItem(
	istream io.Reader, ctrl *CryptCtrl,
	workBuf []byte, citiBuf CitiBuf) (*PackItem, error) {

	var item PackItem

	var kindbuf []byte
	if workBuf != nil {
		kindbuf = workBuf[:1]
	} else {
		kindbuf = make([]byte, 1)
	}
	_, error := io.ReadFull(istream, kindbuf)
	if error != nil {
		return nil, error
	}
	switch item.kind = int8(kindbuf[0]); item.kind {
	case PACKET_KIND_DUMMY:
		return &item, nil
	case PACKET_KIND_SYNC:
		return ReadPackNo(istream, item.kind)
	case PACKET_KIND_NORMAL:
		if item.citiId, error = ReadCitiId(istream); error != nil {
			return nil, error
		}
		var buf []byte
		if workBuf != nil {
			buf = workBuf[:2]
		} else {
			buf = make([]byte, 2)
		}

		//buf := make([]byte,2)
		_, error := io.ReadFull(istream, buf)
		if error != nil {
			return nil, error
		}
		packSize := binary.BigEndian.Uint16(buf)
		var packBuf []byte
		var citiPackBuf []byte = nil
		if workBuf == nil {
			packBuf = make([]byte, packSize)
		} else {
			if len(workBuf) < int(packSize) {
				log.Fatal().Msgf("workbuf size is short: %d", len(workBuf))
			}
			citiPackBuf = citiBuf.GetPacketBuf(item.citiId, packSize)
			if ctrl == nil || !ctrl.dec.IsValid() {
				// Put citiPackBuf directly into packBuf without encryption
				packBuf = citiPackBuf
			} else {
				// If you have encryption, set workBuf in packBuf,
				// set encrypted buffer to citiPackBuf
				packBuf = workBuf[:packSize]
			}
		}
		_, error = io.ReadFull(istream, packBuf)
		if error != nil {
			return nil, error
		}
		if ctrl != nil {
			packBuf = ctrl.dec.Process(packBuf, citiPackBuf)
		}
		item.buf = packBuf
		return &item, nil
	default:
		return nil, fmt.Errorf("ReadItem illegal kind -- %d", item.kind)
	}
}

// load the data
func readItemForNormal(istream io.Reader, ctrl *CryptCtrl) (*PackItem, error) {
	item, err := ReadItem(istream, ctrl, nil, heapCitiBuf)
	if err != nil {
		return nil, err
	}
	if item.kind != PACKET_KIND_NORMAL {
		return nil, fmt.Errorf("readItemForNormal illegal kind -- %d", item.kind)
	}
	return item, nil
}

// load the data
func readItemWithReader(istream io.Reader, ctrl *CryptCtrl) (io.Reader, error) {
	item, err := readItemForNormal(istream, ctrl)
	if err != nil {
		return nil, err
	}
	if item.citiId != CITIID_CTRL {
		return nil, fmt.Errorf("citiid != 0 -- %d", item.citiId)
	}
	return bytes.NewReader(item.buf), nil
}

// server -> client
type AuthChallenge struct {
	Ver       string
	Challenge string
	Mode      string
}

const BENCH_LOOP_COUNT = 200

const CTRL_NONE = 0
const CTRL_BENCH = 1
const CTRL_STOP = 2

// client -> server
type AuthResponse struct {
	//
	Response     string
	Hint         string
	SessionToken string
	WriteNo      int64
	ReadNo       int64
	Ctrl         int
	ForwardList  []Forward
}

// server -> client
type AuthResult struct {
	Result       string
	SessionId    int
	SessionToken string
	WriteNo      int64
	ReadNo       int64
	ForwardList  []Forward
}

func generateChallengeResponse(challenge string, pass *string, hint string) string {
	sum := sha512.Sum512([]byte(challenge + *pass + hint))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Server-side negotiation process
//
// Authenticate the connecting client.
//
// @param connInfo connection connection information
// @param param Tunnel information
// @param remoteAddr Source address
// @return bool true if new session
// @return []Forward Forward list to connect
// @return error
func ProcessServerAuth(
	connInfo *ConnInfo, param *TunnelParam,
	remoteAddr string, forwardList []Forward) (bool, []Forward, error) {

	stream := connInfo.Conn
	log.Print("start auth")

	if err := CorrectLackOffsetWrite(stream); err != nil {
		return false, nil, err
	}
	if err := CorrectLackOffsetRead(stream); err != nil {
		return false, nil, err
	}

	// By encrypting and sending the common string,
	// Send data so that you can check if the encryption password of the connection destination matches
	WriteItem(stream, CITIID_CTRL, []byte(param.magic), connInfo.CryptCtrlObj, nil)

	// create a challenge string
	nano := time.Now().UnixNano()
	sum := sha256.Sum256([]byte(fmt.Sprint("%v", nano)))
	str := base64.StdEncoding.EncodeToString(sum[:])
	challenge := AuthChallenge{"1.00", str, param.Mode}

	bytes, _ := json.Marshal(challenge)
	if err := WriteItem(
		stream, CITIID_CTRL, bytes, connInfo.CryptCtrlObj, nil); err != nil {
		return false, nil, err
	}
	log.Print("challenge ", challenge.Challenge)
	connInfo.SessionInfo.SetState(Session_state_authchallenge)

	// challenge-response processing
	reader, err := readItemWithReader(stream, connInfo.CryptCtrlObj)
	if err != nil {
		return false, nil, err
	}
	var resp AuthResponse
	if err := json.NewDecoder(reader).Decode(&resp); err != nil {
		log.Print("decode error -- AuthResponse")
		return false, nil, err
	}
	if resp.Response != generateChallengeResponse(
		challenge.Challenge, param.pass, resp.Hint) {
		// Authentication failed because challenge-response does not match
		bytes, _ := json.Marshal(AuthResult{"ng", 0, "", 0, 0, nil})
		if err := WriteItem(
			stream, CITIID_CTRL, bytes, connInfo.CryptCtrlObj, nil); err != nil {
			return false, nil, err
		}
		log.Print("mismatch password")
		return false, nil, fmt.Errorf("mismatch password")
	}

	// So far the client has authenticated successfully, so
	// From now on, accept the information notified by the client and OK

	// Take in the sessionId sent by the client
	sessionToken := resp.SessionToken
	newSession := false
	if sessionToken == "" {
		// new session if sessionId is ""
		connInfo.SessionInfo = NewSessionInfo(true)
		newSession = true
	} else {
		if sessionInfo, has := GetSessionInfo(sessionToken); !has {
			mess := fmt.Sprintf("not found session -- %d", sessionToken)
			bytes, _ := json.Marshal(AuthResult{"ng: " + mess, 0, "", 0, 0, nil})
			if err := WriteItem(
				stream, CITIID_CTRL, bytes, connInfo.CryptCtrlObj, nil); err != nil {
				return false, nil, err
			}
			return false, nil, fmt.Errorf(mess)
		} else {
			connInfo.SessionInfo = sessionInfo
			WaitPauseSession(connInfo.SessionInfo)
		}
	}
	log.Printf(
		"sessionId: %s, ReadNo: %d(%d), WriteNo: %d(%d)",
		sessionToken, connInfo.SessionInfo.ReadNo, resp.WriteNo,
		connInfo.SessionInfo.WriteNo, resp.ReadNo)

	// return AuthResult
	bytes, _ = json.Marshal(
		AuthResult{
			"ok", connInfo.SessionInfo.SessionId, connInfo.SessionInfo.SessionToken,
			connInfo.SessionInfo.WriteNo, connInfo.SessionInfo.ReadNo, forwardList})
	log.Printf("sent forwardList -- %v", forwardList)

	if len(forwardList) == 0 {
		forwardList = resp.ForwardList
		log.Printf("receive forwardList -- %v", resp.ForwardList)
	}

	if err := WriteItem(
		stream, CITIID_CTRL, bytes, connInfo.CryptCtrlObj, nil); err != nil {
		return false, nil, err
	}
	log.Print("match password")
	connInfo.SessionInfo.SetState(Session_state_authresult)

	// settings for resending data
	connInfo.SessionInfo.SetReWrite(resp.ReadNo)

	if resp.Ctrl == CTRL_BENCH {
		// benchmark
		benchBuf := make([]byte, 100)
		for count := 0; count < BENCH_LOOP_COUNT; count++ {
			if _, err := ReadItem(
				stream, connInfo.CryptCtrlObj, benchBuf, heapCitiBuf); err != nil {
				return false, nil, err
			}
			if err := WriteItem(
				stream, CITIID_CTRL, benchBuf, connInfo.CryptCtrlObj, nil); err != nil {
				return false, nil, err
			}
		}
		return false, nil, fmt.Errorf("benchmarck")
	}
	if resp.Ctrl == CTRL_STOP {
		log.Print("receive the stop request")
		os.Exit(0)
	}

	SetSessionConn(connInfo)
	// if !newSession {
	// // If it's not a new session, we already have a session in progress, so
	// // Wait for the session to close the connection
	// JoinUntilToCloseConn( stream )
	// }

	return newSession, forwardList, nil
}

func CorrectLackOffsetWrite(stream io.Writer) error {
	// websocket via proxy,
	// Sometimes the first data is missing.
	// Impact of proxy server or websocket implementation problem?
	// I think it's a proxy server problem. .
	// When using WriteItem(), data length and data are sent as a pair, but
	// Lack of data causes inconsistency between data length and data,
	// Attempting to read a nonexistent data length and not returning until timeout.
	// So, to check how much the first data is off
	// Output bytes.
	// Output 0x00 to 0x09 twice.
	bytes := make([]byte, 1)
	for subIndex := 0; subIndex < 2; subIndex++ {
		for index := 0; index < 10; index++ {
			// Output 1 byte at a time because it seems to be missing for each write of stream
			bytes[0] = byte(index)
			if _, err := stream.Write(bytes); err != nil {
				return err
			}
		}
	}
	return nil
}

func CorrectLackOffsetRead(stream io.Reader) error {
	// websocket via proxy,
	// Sometimes the first data is not sent successfully.
	// Now check how much the first data is off.

	// Since there are two bytes from 0x00 to 0x09,
	// read 10 bytes first,
	// load	Check the deviation by looking at the calculated value
	buf := make([]byte, 10)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return err
	}
	log.Printf("num: %x", buf)
	offset := int(buf[0])
	log.Printf("offset: %d", offset)
	if offset >= 10 {
		return fmt.Errorf("illegal num -- %d", offset)
	}

	// read the remaining data according to the amount of deviation
	if _, err := io.ReadFull(stream, buf[:10-offset]); err != nil {
		return err
	}
	log.Printf("num2: %x", buf)
	for index := 0; index < 10-offset; index++ {
		if int(buf[index]) != offset+index {
			return fmt.Errorf(
				"unmatch num -- offset %d: %d != %d", offset, index, buf[index])
		}
	}
	return nil
}

// negotiate with the server
//
// # Exchanging necessary and procedures for client authentication and session information for reconnection
//
// @param connInfo connection. Set the session information when reconnecting.
// @param param TunnelParam
// @return bool Whether to continue processing on error. Continue if true.
// @return error error
func ProcessClientAuth(
	connInfo *ConnInfo, param *TunnelParam,
	forwardList []Forward) ([]Forward, bool, error) {

	log.Print("start auth")

	stream := connInfo.Conn

	if err := CorrectLackOffsetRead(stream); err != nil {
		return nil, true, err
	}
	if err := CorrectLackOffsetWrite(stream); err != nil {
		return nil, true, err
	}

	log.Print("read Magic")
	magicItem, err := readItemForNormal(stream, connInfo.CryptCtrlObj)
	if err != nil {
		return nil, true, err
	}
	if !bytes.Equal(magicItem.buf, []byte(param.magic)) {
		return nil, true, fmt.Errorf("unmatch MAGIC %x", magicItem.buf)
	}
	log.Print("read challenge")

	// Read challenge and generate response from authentication password
	var reader io.Reader
	reader, err = readItemWithReader(stream, connInfo.CryptCtrlObj)
	if err != nil {
		return nil, true, err
	}
	var challenge AuthChallenge
	if err := json.NewDecoder(reader).Decode(&challenge); err != nil {
		return nil, true, err
	}
	log.Print("challenge ", challenge.Challenge)
	// Check server-side mode to check for inconsistencies
	switch challenge.Mode {
	case "server":
		if param.Mode != "client" && param.Mode != "wsclient" {
			return nil, false, fmt.Errorf("unmatch mode -- %s", challenge.Mode)
		}
	case "r-server":
		if param.Mode != "r-client" && param.Mode != "r-wsclient" {
			return nil, false, fmt.Errorf("unmatch mode -- %s", challenge.Mode)
		}
	case "wsserver":
		if param.Mode != "client" && param.Mode != "wsclient" {
			return nil, false, fmt.Errorf("unmatch mode -- %s", challenge.Mode)
		}
	case "r-wsserver":
		if param.Mode != "r-client" && param.Mode != "r-wsclient" {
			return nil, false, fmt.Errorf("unmatch mode -- %s", challenge.Mode)
		}
	}

	// generate response
	nano := time.Now().UnixNano()
	sum := sha256.Sum256([]byte(fmt.Sprint("%v", nano)))
	hint := base64.StdEncoding.EncodeToString(sum[:])
	resp := generateChallengeResponse(challenge.Challenge, param.pass, hint)
	bytes, _ := json.Marshal(
		AuthResponse{
			resp, hint, connInfo.SessionInfo.SessionToken,
			connInfo.SessionInfo.WriteNo,
			connInfo.SessionInfo.ReadNo, param.ctrl, forwardList})
	if err := WriteItem(
		stream, CITIID_CTRL, bytes, connInfo.CryptCtrlObj, nil); err != nil {
		return nil, true, err
	}
	connInfo.SessionInfo.SetState(Session_state_authresponse)

	var result AuthResult
	{
		// get AuthResult
		log.Print("read auth result")
		reader, err := readItemWithReader(stream, connInfo.CryptCtrlObj)
		if err != nil {
			return nil, true, err
		}
		if err := json.NewDecoder(reader).Decode(&result); err != nil {
			return nil, true, err
		}
		if result.Result != "ok" {
			return nil, false, fmt.Errorf("failed to auth -- %s", result.Result)
		}

		log.Printf("received forwardList -- %v", result.ForwardList)
		if result.ForwardList != nil && len(result.ForwardList) > 0 {
			if forwardList != nil {
				// The ForwardList specified by the client, and
				// Check if there is a difference in the ForwardList specified by the server,
				// Output a warning if not.
				orgMap := map[string]bool{}
				for _, forwardInfo := range forwardList {
					orgMap[forwardInfo.String()] = true
				}
				newMap := map[string]bool{}
				for _, forwardInfo := range result.ForwardList {
					newMap[forwardInfo.String()] = true
				}
				diff := false
				if len(orgMap) != len(newMap) {
					diff = true
				} else {
					for org, _ := range orgMap {
						if _, has := newMap[org]; !has {
							diff = true
							break
						}
					}
				}
				if diff {
					log.Printf("******* override forward *******")
					forwardList = result.ForwardList
				}
			} else {
				forwardList = result.ForwardList
			}
		}

		if param.ctrl == CTRL_BENCH {
			// benchmark
			benchBuf := make([]byte, 100)
			prev := time.Now()
			for count := 0; count < BENCH_LOOP_COUNT; count++ {
				if err := WriteItem(
					stream, CITIID_CTRL, benchBuf, connInfo.CryptCtrlObj, nil); err != nil {
					return nil, false, err
				}
				if _, err := ReadItem(
					stream, connInfo.CryptCtrlObj, benchBuf, heapCitiBuf); err != nil {
					return nil, false, err
				}
			}
			duration := time.Now().Sub(prev)

			return nil, false, fmt.Errorf("benchmarck -- %s", duration)
		}
		if param.ctrl == CTRL_STOP {
			os.Exit(0)
		}

		if result.SessionId != connInfo.SessionInfo.SessionId {
			if connInfo.SessionInfo.SessionId == 0 {
				// If it is a new connection, update the session information
				//connInfo.SessionInfo.SessionId = result.SessionId
				connInfo.SessionInfo.UpdateSessionId(
					result.SessionId, result.SessionToken)
			} else {
				return nil, false, fmt.Errorf(
					"illegal sessionId -- %d, %d",
					connInfo.SessionInfo.SessionId, result.SessionId)
			}
		}

		log.Printf(
			"sessionId: %d, ReadNo: %d(%d), WriteNo: %d(%d)",
			result.SessionId, connInfo.SessionInfo.ReadNo, result.WriteNo,
			connInfo.SessionInfo.WriteNo, result.ReadNo)
		connInfo.SessionInfo.SetReWrite(result.ReadNo)
	}

	return forwardList, true, nil
}
