package kptunnel

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog/log"
	"io"
)

type Transport struct {
	Conn      io.ReadWriteCloser // connection
	CryptCtrl *CryptCtrl         // encrypted information
	Session   *Session           // session information
}

func newTransport(conn io.ReadWriteCloser, pass *string, count int, session *Session, isTunnelServer bool) *Transport {
	if session == nil {
		session = newEmptySession(0, "", isTunnelServer)
	}
	return &Transport{Conn: conn, CryptCtrl: CreateCryptCtrl(pass, count), Session: session}
}

// write data to connection, save the written data in WritePackList.
func (t *Transport) writeNormalPacket(streamWriter io.Writer, tunnelStreamId uint32, bytes []byte) error {
	return writeBytesAsNormalPacketWithBuffer(streamWriter, tunnelStreamId, bytes, t.CryptCtrl, nil) // TBD use &transport.WriteBuffer as the buffer
	// return writeBytesAsNormalPacket(streamWriter, streamId, bytes, transport.CryptCtrl)
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
func (t *Transport) readNormalPacket(work []byte) (*Packet, error) {
	// read infinitely until a normal packet, or error happens
	log.Info().Msgf("going into the loop to read a normal packet ...")
	for {
		pkt, err := readPacketFromConn(t.Conn, t.CryptCtrl, work, t.Session)
		if err != nil {
			log.Err(err).Msgf("read from conn failed")
			return nil, err
		}

		// increase ReadNo, note: dummy pkt is actually not processed
		if pkt.kind != PACKET_KIND_DUMMY {
			t.Session.ReadNo++
			log.Debug().Msgf("packet read, updated session ReadNo: %d", t.Session.ReadNo)
		}

		if pkt.kind == PACKET_KIND_SYNC {
			log.Debug().Msgf("get sync packet, %s", pkt.String())

			// Update syncChan when the other party receives it and set it to proceed with transmission processing.
			if citi := t.Session.getTunnelStream(pkt.streamId); citi != nil {
				citi.syncChan <- true
				log.Debug().Msgf("stream %d found, sync is put into syncChan", citi)
			} else {
				log.Debug().Msgf("stream %d not found, discard sync pkt", pkt.streamId)
			}
		}

		if pkt.kind == PACKET_KIND_NORMAL {
			log.Info().Msgf("normal pkt read, %s", pkt.String())
			t.Session.readSize += int64(len(pkt.bytes))
			return pkt, nil
		}
	}
}

// goroutine for conn => local stream (packetChan)
func readLocalTransport(localStream *LocalStream, session *Session, exitChan chan<- bool) {
	sessionId := session.Id
	packetChan := session.packetChan

	for {
		if (localStream.WriteNo % PACKET_NUM_BASE) == 0 {
			log.Debug().Msgf("WriteNo: %d, waiting for sync packet ...", localStream.WriteNo)
			// In order to leave a buffer for retransmission when reconnecting after tunnel disconnection, get syncChan for every PACKET_NUM_BASE
			// Don't send too much when the other party hasn't received it.
			<-localStream.syncChan // TODO wait for sync signal, how is it triggered?
			log.Debug().Int("sessionId", sessionId).Msgf("sync packet captured")
		}
		localStream.WriteNo++

		buf := localStream.ringBufW.getNext() // switch buffer
		readSize, readErr := localStream.conn.Read(buf)

		log.Debug().Int("sessionId", sessionId).Msgf("bytes read, size: %d bytes, stream %d readNo: %d, WriteNo: %d, ",
			readSize, localStream.Id, localStream.ReadNo, localStream.WriteNo)
		if readErr != nil {
			log.Err(readErr).Int("sessionId", sessionId).Msgf("conn bytes reading err, writeNo: %d", session.WriteNo)
			packetChan <- Packet{bytes: make([]byte, 0), kind: PACKET_KIND_NORMAL, streamId: localStream.Id} // write 0 bytes data to the destination when the input source is dead
			log.Info().Int("sessionId", sessionId).Msgf("0-size normal packet pushed to packetChan")
			break
		}
		if readSize == 0 {
			log.Warn().Int("sessionId", session.Id).Msg("ignore 0-size packet")
			continue
		}

		if (localStream.WriteNo%PACKET_NUM_BASE) == 0 && len(localStream.syncChan) == 0 {
			work := <-localStream.syncChan // if it's the last packet in the packet group and packetNumber SYNC is coming, wait for SYNC before sending
			localStream.syncChan <- work   // Since we read ahead SYNC, we write back SYNC.
		}

		packetChan <- Packet{bytes: buf[:readSize], kind: PACKET_KIND_NORMAL, streamId: localStream.Id}
		log.Debug().Int("sessionId", sessionId).Msgf("normal packet pushed to packetChan")
	}

	exitChan <- true
	log.Info().Int("sessionId", sessionId).Msgf("read from local transport is done")
}

// tunnel stream (bytesChan) => conn
func writeLocalTransport(session *Session, localStream *LocalStream, exitChan chan<- bool) {
	for {
		readBuf := <-localStream.bytesChan

		readSize := len(readBuf)
		log.Debug().Msgf("read from bytes channel, readNo: %d, size: %d", localStream.ReadNo, readSize)

		if (localStream.ReadNo % PACKET_NUM_BASE) == PACKET_NUM_BASE-1 { // send SYNC after reading a certain number
			var buffer bytes.Buffer
			_ = binary.Write(&buffer, binary.BigEndian, localStream.ReadNo)
			session.packetChan <- Packet{bytes: buffer.Bytes(), kind: PACKET_KIND_SYNC, streamId: localStream.Id} // push sync packet
			log.Info().Msg("sync sent to packet chan")
		}
		localStream.ReadNo++

		if readSize == 0 {
			log.Warn().Msgf("read 0-size from bytes channel, exit")
			break
		}

		_, writeErr := localStream.conn.Write(readBuf)
		if writeErr != nil {
			log.Err(writeErr).Msgf("conn writing failed, readNo: %d, exit", localStream.ReadNo)
			break
		}
	}

	session.delTunnelStream(localStream) // Remove data from localStream.bytesChan to prevent stuffing
	exitChan <- true
	log.Info().Int("sessionId", session.Id).Msgf("write to local transport is done")
}

// Mux tunnel stream between transport stream
func relayLocalTransport(session *Session, stream *LocalStream) {
	exitChan := make(chan bool)
	go readLocalTransport(stream, session, exitChan)  // local conn read: session packetChan <= local conn
	go writeLocalTransport(session, stream, exitChan) // local conn write: LocalStream bytesChan => local conn

	<-exitChan
	_ = stream.conn.Close()
	<-exitChan
	log.Info().Msgf("local transport relay is done")
}

// initiate a new tcp connection
func establishNewConnection(dialer func(dst string) (io.ReadWriteCloser, error), addr string, streamId uint32, session *Session) {
	conn, err := dialer(addr)

	sessionId := session.Id
	localStream := session.addTunnelStream(conn, streamId)

	{ // push ctrl_resp
		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_RESP_CONNECTION_ESTABLISHED})
		resp := CtrlResponse{Success: err == nil, Message: fmt.Sprint(err), LocalStreamId: streamId}
		buf, _ := json.Marshal(&resp)
		buffer.Write(buf)
		session.packetChan <- Packet{bytes: buffer.Bytes(), kind: PACKET_KIND_NORMAL, streamId: TUNNEL_STREAM_ID_CTRL} // ctrl_resp pushed
		log.Info().Int("sessionId", sessionId).Msg("ctrl resp ctrlRequestChan pushed into packetChan")

		if err != nil { // note this is the dialing error
			log.Err(err).Int("sessionId", sessionId).Msgf("fail to dial %s", addr)
			return
		}
	}
	defer func() { _ = conn.Close() }()

	log.Info().Int("sessionId", sessionId).Msgf("connected to %s, star relaying ...", addr)
	relayLocalTransport(session, localStream) // client side, connect and mux

	log.Info().Int("sessionId", sessionId).Msgf("connection to %s closed", addr)
}

func acceptAndRelay(listener LocalListener, session *Session) {
	sessionId := session.Id

	log.Info().Int("sessionId", sessionId).
		Msgf("listening connections at %s ... (%s)", listener.forward.Src.String(), listener.forward.String())
	conn, err := listener.listener.Accept()
	if err != nil {
		log.Fatal().Err(err)
	}
	willCloseConn := true
	defer func() {
		if willCloseConn {
			log.Info().Msgf("close the client connection")
			_ = conn.Close()
		}
	}()

	log.Info().Int("sessionId", sessionId).Msgf("new connection accepted")

	tunnelStream := session.addTunnelStream(conn, TUNNEL_STREAM_ID_CTRL)
	dest := listener.forward.Dest

	// push ctrl_req, notify the other party to initiate new connection
	{
		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_REQ_NEW_CONNECTION})
		buf, _ := json.Marshal(&CtrlRequest{Host: dest, LocalStreamId: tunnelStream.Id})
		buffer.Write(buf)
		session.packetChan <- Packet{bytes: buffer.Bytes(), kind: PACKET_KIND_NORMAL, streamId: TUNNEL_STREAM_ID_CTRL} // accept a new connection, push ctrl_req_header to notify the other party
		log.Info().Int("sessionId", sessionId).Msgf("ctrl_req pushed to packetChan(%v), waiting ctrl_resp ...", session.packetChan)
	}

	ctrlResp := <-tunnelStream.ctrlRespChan
	if !ctrlResp.Success {
		log.Error().Int("sessionId", sessionId).Msgf("ctrl_resp failed, dest: %s, message: %s", dest.String(), ctrlResp.Message)
		return
	}
	log.Info().Int("sessionId", sessionId).Msgf("ctrl_resp received, mux accepted connection")
	go relayLocalTransport(session, tunnelStream) // server side, accept and mux

	log.Info().Msgf("ctrl negotiation succeeds, will not close client connection")
	willCloseConn = false
}

func acceptAndRelayForeverGR(listener LocalListener, session *Session) {
	for {
		acceptAndRelay(listener, session)
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
