// -*- coding: utf-8 -*-
package kptunnel

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

const BUFSIZE = 65535

type Host struct {
	Scheme string
	Name   string
	Port   int
	Path   string
	Query  string
}

func (info *Host) String() string {
	repr := fmt.Sprintf("%s%s:%d%s", info.Scheme, info.Name, info.Port, info.Path)
	if info.Query != "" {
		repr = fmt.Sprintf("%s?%s", repr, info.Query)
	}
	return repr
}

func Hostname2HostInfo(name string) *Host {
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
	return &Host{"", hostport[0], port, serverUrl.Path, serverUrl.RawQuery}
}

// パスワードからキーを生成する
func GetKey(pass []byte) []byte {
	sum := sha256.Sum256(pass)
	return sum[:]
}

// 暗号化モード
type CryptMode struct {
	// 暗号化を行なう最大回数。
	// -1: 無制限
	//  0: 暗号化なし
	//  N: 最大暗号化回数 N 回
	countMax int
	// 現在の暗号化回数
	count int
	// 作業用バッファ
	work []byte
	// 暗号化処理
	stream cipher.Stream
}
type CryptCtrl struct {
	enc CryptMode
	dec CryptMode
}

// 暗号用のオブジェクトを生成する
//
// @param pass パスワード
// @param count 暗回化回数
func CreateCryptCtrl(pass *string, count int) *CryptCtrl {
	if pass == nil || count == 0 {
		return nil
	}

	bufSize := BUFSIZE
	key := GetKey([]byte(*pass))
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

// 暗号・複合処理
//
// @param inbuf 処理対象のデータを保持するバッファ
// @param outbuf 処理後のデータを格納するバッファ。
//
//	nil を指定した場合 CryptMode の work に結果を格納する。
//
// @return 処理後のデータを格納するバッファ。
//
//	outbuf に nil 以外を指定した場合、 outbuf の slice を返す。
//	outbuf に nil を指定した場合、CryptMode の work の slice を返す。
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
	// bytes := work[:len(inbuf)]
	// mode.stream.XORKeyStream( bytes, inbuf )
	// return bytes

	mode.stream.XORKeyStream(work, inbuf)

	return work[:len(inbuf)]
}

// 暗号化
func (ctrl *CryptCtrl) Encrypt(bytes []byte) []byte {
	return ctrl.enc.Process(bytes, nil)
}

// 複合化
func (ctrl *CryptCtrl) Decrypt(bytes []byte) []byte {
	return ctrl.dec.Process(bytes, nil)
}

const PACKET_KIND_NORMAL = 0 // normal packet
const PACKET_KIND_DUMMY = 1  // dummy packet as heartbeat
const PACKET_KIND_EOS = 2    // Packet for notifying the shouldEnd of stream
const PACKET_KIND_SYNC = 3   // Packet for communication synchronization
const PACKET_KIND_NORMAL_DIRECT = 4

func getKindName(kind int8) string {
	switch kind {
	case PACKET_KIND_NORMAL:
		return "normal"
	case PACKET_KIND_DUMMY:
		return "dummy"
	case PACKET_KIND_EOS:
		return "eos"
	case PACKET_KIND_SYNC:
		return "sync"
	case PACKET_KIND_NORMAL_DIRECT:
		return "normal-direct"
	default:
		return "unknown"
	}
}

// DummyKindBuf and followings are all 1 byte length, and are initialized with constants
var DummyKindBuf = []byte{PACKET_KIND_DUMMY}
var NormalKindBuf = []byte{PACKET_KIND_NORMAL}
var SyncKindBuf = []byte{PACKET_KIND_SYNC}

var PACKET_LEN_HEADER int = 0

func init() {
	var citiId uint32
	PACKET_LEN_HEADER = len(NormalKindBuf) + int(unsafe.Sizeof(citiId))
}

func writeBytesAsNormalPacketWithBuffer(writer io.Writer, tunnelStreamId uint32, buf []byte, ctrl *CryptCtrl, inputBuffer *bytes.Buffer) error {
	// If the number of write calls is large, the communication efficiency is poor.
	// Write to buffer first and then output to stream.
	var buffer = inputBuffer
	if buffer == nil {
		buffer = &bytes.Buffer{}
	} else {
		buffer.Reset()
	}
	size := uint16(len(buf))
	buffer.Grow(len(NormalKindBuf) + int(unsafe.Sizeof(tunnelStreamId)) + int(unsafe.Sizeof(size)) + len(buf))
	if err := writeBytesAsNormalPacket(buffer, tunnelStreamId, buf, ctrl); err != nil {
		return err
	}

	_, err := buffer.WriteTo(writer)
	return err
}

func writeBytesAsNormalPacket(writer io.Writer, tunnelStreamId uint32, buf []byte, cryptCtrl *CryptCtrl) error {
	// kind
	if _, err := writer.Write(NormalKindBuf); err != nil {
		return err
	}
	// tunnelStreamId
	if err := binary.Write(writer, binary.BigEndian, tunnelStreamId); err != nil {
		return err
	}

	if cryptCtrl != nil { // encrypt the buffer
		buf = cryptCtrl.enc.Process(buf, nil)
	}
	// bytes size
	if err := binary.Write(writer, binary.BigEndian, uint16(len(buf))); err != nil {
		return err
	}
	// buffer
	_, err := writer.Write(buf)
	return err
}

func ReadTunnelStreamId(reader io.Reader) (uint32, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf), nil
}

func ReadPackNo(reader io.Reader, kind int8) (*Packet, error) {
	var item Packet
	item.kind = kind
	var err error
	if item.tunnelStreamId, err = ReadTunnelStreamId(reader); err != nil {
		return nil, err
	}
	var packNo int64
	item.bytes = make([]byte, unsafe.Sizeof(packNo))
	_, err = io.ReadFull(reader, item.bytes)
	if err != nil {
		return &item, err
	}
	return &item, nil
}

type CitiBuf interface {
	// GetPacketBuf gets buffer for Id
	GetPacketBuf(citiId uint32, packSize uint16) []byte
}

type HeapCitiBuf struct{}

var heapCitiBuf *HeapCitiBuf = &HeapCitiBuf{}

func (citiBuf *HeapCitiBuf) GetPacketBuf(citiId uint32, packSize uint16) []byte {
	return make([]byte, packSize)
}

// read packet from conn
func readPacketFromConn(reader io.Reader, ctrl *CryptCtrl, workBuf []byte, citiBuf CitiBuf) (*Packet, error) {
	var packetItem Packet

	// read kind, 1 byte
	var kindBuf []byte
	if workBuf != nil {
		kindBuf = workBuf[:1]
	} else {
		kindBuf = make([]byte, 1)
	}
	_, err := io.ReadFull(reader, kindBuf)
	if err != nil {
		return nil, err
	}

	switch packetItem.kind = int8(kindBuf[0]); packetItem.kind {
	case PACKET_KIND_DUMMY:
		return &packetItem, nil
	case PACKET_KIND_SYNC:
		return ReadPackNo(reader, packetItem.kind)
	case PACKET_KIND_NORMAL:
		if packetItem.tunnelStreamId, err = ReadTunnelStreamId(reader); err != nil {
			return nil, err
		}

		// read packet size, 2 bytes
		var packetSizeBuf []byte
		if workBuf != nil {
			packetSizeBuf = workBuf[:2]
		} else {
			packetSizeBuf = make([]byte, 2)
		}

		_, err := io.ReadFull(reader, packetSizeBuf)
		if err != nil {
			return nil, err
		}
		packetSize := binary.BigEndian.Uint16(packetSizeBuf)

		var packetBuf []byte
		var citiPackBuf []byte = nil
		if workBuf == nil {
			packetBuf = make([]byte, packetSize)
		} else {
			if len(workBuf) < int(packetSize) { // should be: 1 + 2 + packetSize bytes
				log.Fatal().Msgf("packet buffer is less than expected, raw size: %d, expect: %d", len(workBuf), packetBuf)
			}
			citiPackBuf = citiBuf.GetPacketBuf(packetItem.tunnelStreamId, packetSize)
			if ctrl == nil || !ctrl.dec.IsValid() {
				packetBuf = citiPackBuf // put citiPackBuf directly in packetBuf if packetNumber encryption
			} else {
				packetBuf = workBuf[:packetSize] // If encryption is enabled, set packetBuf to workBuf, set encrypted buffer to citiPackBuf
			}
		}
		_, err = io.ReadFull(reader, packetBuf)
		if err != nil {
			return nil, err
		}
		if ctrl != nil {
			packetBuf = ctrl.dec.Process(packetBuf, citiPackBuf)
		}
		packetItem.bytes = packetBuf
		return &packetItem, nil
	default:
		return nil, fmt.Errorf("illegal kind: %d", packetItem.kind)
	}
}

func getNormalPacketOrError(reader io.Reader, ctrl *CryptCtrl) (*Packet, error) {
	packetItem, err := readPacketFromConn(reader, ctrl, nil, heapCitiBuf)
	if err != nil {
		return nil, err
	}
	if packetItem.kind != PACKET_KIND_NORMAL {
		return nil, fmt.Errorf("expect normal packet, get kind: %d", packetItem.kind)
	}
	return packetItem, nil
}

func getNormalPacketBufReaderOrError(reader io.Reader, ctrl *CryptCtrl) (io.Reader, error) {
	packetItem, err := getNormalPacketOrError(reader, ctrl)
	if err != nil {
		return nil, err
	}
	if packetItem.tunnelStreamId != TUNNEL_STREAM_ID_CTRL {
		return nil, fmt.Errorf("expect CIT CTRL, get %d", packetItem.tunnelStreamId)
	}
	return bytes.NewReader(packetItem.bytes), nil
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
// Authenticate the isConnecting client.
//
// @param transport connection information
// @param param Tunnel information
// @param remoteAddr Source address
// @return bool true if new session
// @return []Forward list of Forward to connect
// @return error
func handleAuthOnServerSide(connInfo *Transport, param *TunnelParam, remoteAddr string, forwardList []Forward) (bool, []Forward, error) {
	stream := connInfo.Conn
	log.Print("start server auth")

	if err := CorrectLackOffsetWrite(stream); err != nil {
		return false, nil, err
	}
	if err := CorrectLackOffsetRead(stream); err != nil {
		return false, nil, err
	}

	_ = writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, param.Magic, connInfo.CryptCtrl, nil) // write magic

	nano := time.Now().UnixNano()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v", nano)))
	str := base64.StdEncoding.EncodeToString(sum[:])
	challenge := AuthChallenge{"1.00", str, param.Mode}

	buf, _ := json.Marshal(challenge)
	if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, buf, connInfo.CryptCtrl, nil); err != nil { // write challenge
		return false, nil, err
	}
	log.Print("challenge ", challenge.Challenge)
	connInfo.Session.SetState(Session_state_authchallenge)

	// challenge-response processing
	reader, err := getNormalPacketBufReaderOrError(stream, connInfo.CryptCtrl)
	if err != nil {
		return false, nil, err
	}
	var resp AuthResponse
	if err := json.NewDecoder(reader).Decode(&resp); err != nil {
		log.Warn().Msgf("AuthResponse decoding error")
		return false, nil, err
	}
	if resp.Response != generateChallengeResponse(challenge.Challenge, param.Pass, resp.Hint) {
		// authentication failed because challenge-response does not match
		buf, _ := json.Marshal(AuthResult{"ng", 0, "", 0, 0, nil})
		if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, buf, connInfo.CryptCtrl, nil); err != nil { // write AuthResult failure
			return false, nil, err
		}
		log.Print("password mismatches")
		return false, nil, fmt.Errorf("password mismatches")
	}

	// ここまででクライアントの認証が成功したので、
	// これ以降はクライアントが通知してきた情報を受けいれて OK

	// クライアントが送ってきた sessionId を取り入れる
	sessionToken := resp.SessionToken
	newSession := false
	if sessionToken == "" {
		// sessionId が "" なら、新規セッション
		connInfo.Session = NewSessionInfo(true)
		newSession = true
	} else {
		if sessionInfo, has := GetSessionInfo(sessionToken); !has {
			errorMessage := fmt.Sprintf("session [%s] not found", sessionToken)
			buf, _ := json.Marshal(AuthResult{Result: errorMessage})
			if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, buf, connInfo.CryptCtrl, nil); err != nil { // write AuthResult session not found error
				return false, nil, err
			}
			return false, nil, fmt.Errorf(errorMessage)
		} else {
			connInfo.Session = sessionInfo
			WaitPauseSession(connInfo.Session)
		}
	}
	log.Printf("sessionId: %s, ReadNo: %d(%d), WriteNo: %d(%d)", sessionToken, connInfo.Session.ReadNo, resp.WriteNo, connInfo.Session.WriteNo, resp.ReadNo)

	// return AuthResult
	buf, _ = json.Marshal(AuthResult{
		Result:       "ok",
		SessionId:    connInfo.Session.Id,
		SessionToken: connInfo.Session.Token,
		WriteNo:      connInfo.Session.WriteNo,
		ReadNo:       connInfo.Session.ReadNo,
		ForwardList:  forwardList,
	})
	log.Info().Msgf("forwards sent: %v", forwardList)
	if len(forwardList) == 0 {
		forwardList = resp.ForwardList
		log.Info().Msgf("forwards received: %v", resp.ForwardList)
	}
	if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, buf, connInfo.CryptCtrl, nil); err != nil { // write AuthResult
		return false, nil, err
	}
	log.Info().Msgf("password verified")

	connInfo.Session.SetState(Session_state_authresult)
	connInfo.Session.SetReWrite(resp.ReadNo) // settings for resending data

	if resp.Ctrl == CTRL_BENCH {
		benchBuf := make([]byte, 100)
		for count := 0; count < BENCH_LOOP_COUNT; count++ {
			if _, err := readPacketFromConn(stream, connInfo.CryptCtrl, benchBuf, heapCitiBuf); err != nil {
				return false, nil, err
			}
			if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, benchBuf, connInfo.CryptCtrl, nil); err != nil { // write benchmark buffer
				return false, nil, err
			}
		}
		return false, nil, fmt.Errorf("benchmarck is done")
	}

	if resp.Ctrl == CTRL_STOP {
		log.Info().Msgf("received the stop request, exit now")
		os.Exit(0)
	}

	SetSessionConn(connInfo)

	log.Info().Msgf("server auth completes")
	return newSession, forwardList, nil
}

func CorrectLackOffsetWrite(stream io.Writer) error {
	// proxy 経由の websocket だと、
	// 最初のデータが欠けることがある。
	// proxy サーバの影響か、 websocket の実装上の問題か？
	// proxy サーバの問題な気がするが。。
	// writeBytesAsNormalPacketWithBuffer() を使うと、データ長とデータがペアで送信されるが、
	// データが欠けることでデータ長とデータに不整合が発生し、
	// 存在しないデータ長を読みこもうとして、タイムアウトするまで戻ってこない。
	// そこで、最初のデータにどれだけズレがあるかを確認するための
	// バイト列を出力する。
	// 0x00 〜 0x09 を2回出力する。
	bytes := make([]byte, 1)
	for subIndex := 0; subIndex < 2; subIndex++ {
		for index := 0; index < 10; index++ {
			// stream の write ごとに欠けるようなので、1 バイトづつ出力する
			bytes[0] = byte(index)
			if _, err := stream.Write(bytes); err != nil {
				return err
			}
		}
	}
	return nil
}

func CorrectLackOffsetRead(stream io.Reader) error {
	// proxy 経由の websocket だと、
	// 最初のデータが正常に送信されないことがある。
	// ここで、最初のデータにどれだけズレがあるかを確認する。

	// 0x00 〜 0x09 までのバイト列が 2 回あるので、
	// 最初に 10 バイト読み込み、
	// 読み込めた値を見てズレを確認する
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

	// ズレ量に応じて残りのデータを読み込む
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
// Exchanging necessary and procedures for client authentication and session information for reconnection
//
// @param transport connection. Set the session information when reconnecting.
// @param param TunnelParam
// @return bool Whether to continue processing on error. Continue if true.
// @return error
func handleAuthOnClientSide(connInfo *Transport, param *TunnelParam, forwardList []Forward) ([]Forward, bool, error) {
	log.Printf("client starts auth ... (forwards: %v)", forwardList)

	stream := connInfo.Conn

	if err := CorrectLackOffsetRead(stream); err != nil {
		return nil, true, err
	}
	if err := CorrectLackOffsetWrite(stream); err != nil {
		return nil, true, err
	}

	log.Print("read Magic")
	magicItem, err := getNormalPacketOrError(stream, connInfo.CryptCtrl)
	if err != nil {
		return nil, true, err
	}
	if !bytes.Equal(magicItem.bytes, []byte(param.Magic)) {
		return nil, true, fmt.Errorf("unmatch MAGIC %x", magicItem.bytes)
	}
	log.Print("read challenge")

	// challenge を読み込み、認証用パスワードから response を生成する
	var reader io.Reader
	reader, err = getNormalPacketBufReaderOrError(stream, connInfo.CryptCtrl)
	if err != nil {
		return nil, true, err
	}
	var challenge AuthChallenge
	if err := json.NewDecoder(reader).Decode(&challenge); err != nil {
		return nil, true, err
	}
	log.Print("challenge ", challenge.Challenge)
	// サーバ側のモードを確認して、不整合がないかチェックする
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

	// generate auth response
	nano := time.Now().UnixNano()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%v", nano)))
	hint := base64.StdEncoding.EncodeToString(sum[:])
	resp := generateChallengeResponse(challenge.Challenge, param.Pass, hint)
	buf, _ := json.Marshal(AuthResponse{
		Response:     resp,
		Hint:         hint,
		SessionToken: connInfo.Session.Token,
		WriteNo:      connInfo.Session.WriteNo,
		ReadNo:       connInfo.Session.ReadNo,
		Ctrl:         param.Ctrl,
		ForwardList:  forwardList,
	})
	if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, buf, connInfo.CryptCtrl, nil); err != nil { // write AuthResponse
		return nil, true, err
	}
	connInfo.Session.SetState(Session_state_authresponse)

	var result AuthResult
	{
		// AuthResult を取得する
		log.Print("read auth result")
		reader, err := getNormalPacketBufReaderOrError(stream, connInfo.CryptCtrl)
		if err != nil {
			return nil, true, err
		}
		if err := json.NewDecoder(reader).Decode(&result); err != nil {
			return nil, true, err
		}
		if result.Result != "ok" {
			return nil, false, fmt.Errorf("failed to auth -- %s", result.Result)
		}

		log.Printf("received forwards from remote: %v", result.ForwardList)
		if result.ForwardList != nil && len(result.ForwardList) > 0 {
			if forwardList != nil {
				// クライアントが指定している ForwardList と、
				// サーバ側が指定している ForwardList に違いがあるか調べて、
				// 違う場合は警告を出力する。
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

		if param.Ctrl == CTRL_BENCH {
			benchBuf := make([]byte, 100)
			prev := time.Now()
			for count := 0; count < BENCH_LOOP_COUNT; count++ {
				if err := writeBytesAsNormalPacketWithBuffer(stream, TUNNEL_STREAM_ID_CTRL, benchBuf, connInfo.CryptCtrl, nil); err != nil { // write benchmark buffer
					return nil, false, err
				}
				if _, err := readPacketFromConn(stream, connInfo.CryptCtrl, benchBuf, heapCitiBuf); err != nil {
					return nil, false, err
				}
			}
			duration := time.Now().Sub(prev)

			return nil, false, fmt.Errorf("benchmarck -- %s", duration)
		}

		if param.Ctrl == CTRL_STOP {
			os.Exit(0)
		}

		if result.SessionId != connInfo.Session.Id {
			if connInfo.Session.Id == 0 {
				// 新規接続だった場合、セッション情報を更新する
				//transport.Session.Id = result.Id
				connInfo.Session.UpdateSessionId(result.SessionId, result.SessionToken)
			} else {
				return nil, false, fmt.Errorf("illegal sessionId -- %d, %d",
					connInfo.Session.Id, result.SessionId)
			}
		}

		log.Printf("sessionId: %d, ReadNo: %d(%d), WriteNo: %d(%d)", result.SessionId, connInfo.Session.ReadNo, result.WriteNo, connInfo.Session.WriteNo, result.ReadNo)
		connInfo.Session.SetReWrite(result.ReadNo)
	}

	log.Printf("client auth completes")
	return forwardList, true, nil
}
