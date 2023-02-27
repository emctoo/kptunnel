package kptunnel

import (
	"bytes"
	"encoding/json"
	"github.com/rs/zerolog/log"
	"time"
)

// Mux controls information that muxMap communication between tunnel and connection destination
type Mux struct {
	revision             int                               // Revision of tunnel conn/transport. Counts up each time reconnection is established.
	reconnectFn          func(session *Session) *Transport // give up reconnection when it returns nil (reconnection failed)
	shouldEnd            bool                              // true when this Tunnel connection should be terminated
	exitChan             chan bool                         // Channel for waiting for the shouldEnd of relay processing
	isConnecting         bool                              // true while reconnecting
	transport            *Transport                        // Connection information isConnecting pipe
	isTunnelStreamServer bool                              // true if it's server
}

func newMux(transport *Transport, isTunnelStreamServer bool, reconnect func(session *Session) *Transport) (*Mux, bool) {
	sessionMgr.mutex.get("newMux")
	defer sessionMgr.mutex.rel()

	session := transport.Session
	mux, exists := sessionMgr.muxMap[session.Id]
	if exists {
		return mux, false
	}

	mux = &Mux{
		reconnectFn:          reconnect,
		transport:            transport,
		exitChan:             make(chan bool),
		isTunnelStreamServer: isTunnelStreamServer,
	}
	sessionMgr.muxMap[session.Id] = mux
	return mux, true
}

func (mux *Mux) sendRelease() {
	if mux.isTunnelStreamServer {
		releaseChan := mux.transport.Session.releaseChan //
		if len(releaseChan) == 0 {
			releaseChan <- true
		}
	}
}

// @param revision current revision
// @return Transport connection after reconnection
// @return int Revision after reconnection
// @return bool Whether to terminate the session. true to terminate
func (mux *Mux) reconnect(rev int) (*Transport, int, bool) {
	workRev, workConnInfo := mux.getRevAndTransport()
	session := mux.transport.Session

	session.mutex.get("reconnect")
	session.reconnetWaitState++
	session.mutex.rel()

	log.Printf("tunnel transport reconnecting, revision: %d", rev)

	reqConnect := false

	sub := func() bool {
		session.mutex.get("reconnect-sub")
		defer session.mutex.rel()

		if mux.revision != rev {
			if !mux.isConnecting {
				session.reconnetWaitState--
				workRev = mux.revision
				workConnInfo = mux.transport
				return true
			}
		} else {
			mux.isConnecting = true
			mux.revision++
			reqConnect = true
			return true
		}
		return false
	}

	if mux.reconnectFn != nil {
		for {
			if sub() {
				break
			}

			time.Sleep(500 * time.Millisecond)
		}
	} else {
		reqConnect = true
		mux.revision++
	}

	if reqConnect {
		releaseSessionTransport(mux)
		reverseTunnelPreCloseHook(mux)

		if len(session.packetChan) == 0 {
			// Don't stop writeTunnelTransportGR waiting for session.packetChan, throw dummy.
			session.packetChan <- Packet{kind: PACKET_KIND_DUMMY, streamId: TUNNEL_STREAM_ID_CTRL}
		}

		if !mux.shouldEnd {
			session.SetState(Session_state_reconnecting)

			workRev = mux.revision
			workInfo := mux.reconnectFn(session)
			if workInfo != nil {
				mux.transport = workInfo
				log.Printf("new transport -- %p", workInfo)
				session.SetState(Session_state_connected)
			} else {
				mux.shouldEnd = true
				mux.transport = newTransport(dummyConn, nil, 0, session, session.isTunnelServer)
				log.Printf("set dummyConn")
			}
			workConnInfo = mux.transport

			func() {
				session.mutex.get("reconnectFn-shouldEnd")
				defer session.mutex.rel()
				session.reconnetWaitState--
			}()

			mux.isConnecting = false
		}
	}

	log.Printf("reconnection succeeds")
	return workConnInfo, workRev, mux.shouldEnd
}

func releaseSessionTransport(mux *Mux) {
	transport := mux.transport
	log.Debug().Int("sessionId", transport.Session.Id).Msgf("release transport")

	sessionMgr.mutex.get("releaseSessionTransport")
	defer sessionMgr.mutex.rel()

	//delete(sessionMgr.conn2alive, transport.Conn)
	delete(sessionMgr.transportMap, transport.Session.Id)

	_ = transport.Conn.Close()
	mux.sendRelease()
}

// get connection information
//
// @return int revision information
// @return *Transport connection information
func (mux *Mux) getRevAndTransport() (int, *Transport) {
	// TODO necessary?
	session := mux.transport.Session
	session.mutex.get("getRevAndTransport")
	defer session.mutex.rel()

	return mux.revision, mux.transport
}

// tunnel transport => tunnelStream bytesChan
func readTunnelTransportGR(mux *Mux) {
	rev, tunnelTransport := mux.getRevAndTransport()
	session := tunnelTransport.Session

	log.Info().Msgf("tunnelTransport reader goroutine starts ...")
	buf := make([]byte, BUFSIZE)
	for {
		readSize := 0
		var localStream *LocalStream
		for {
			packet, err := tunnelTransport.readNormalPacket(buf)
			if err != nil {
				log.Err(err).Msgf("fail to read from tunnel transport, readNo: %d", session.ReadNo)

				_ = tunnelTransport.Conn.Close()
				log.Warn().Msgf("tunnel transport closed")

				log.Info().Msgf("reconnecting tunnel transport ...")
				end := false
				tunnelTransport, rev, end = mux.reconnect(rev) // tunnel transport, fail to read, try to reconnect
				if end {
					log.Info().Msgf("tunnel transport reconnecting ends, quit reading now ...")
					readSize = 0
					mux.shouldEnd = true
					break
				}
				continue
			}

			log.Debug().Msgf("packet read, readNo: %d, %s", session.ReadNo, packet.String())
			if packet.streamId == TUNNEL_STREAM_ID_CTRL {
				log.Debug().Msgf("control packet")
				handleControlPacket(session, packet.bytes)
				readSize = 1 // set readSize to 1 so that the process doesn't shouldEnd
				break
			}
			localStream = session.getTunnelStream(packet.streamId)
			if localStream == nil {
				log.Info().Msgf("stream %d not found, discard the packet", packet.streamId)
				readSize = 1
			}

			// packet.bytes to localStream.bytesChan
			// put in and processed in another thread.
			// On the other hand, packet.bytes refers to a fixed address, so if you readNormalPacket before processing in another thread, the contents of packet.bytes will be overwritten.
			// Copy to prevent that.

			// cloneBuf := localStream.ringBufR.getNext()[:len(packet.bytes)]
			// copy( cloneBuf, packet.bytes )
			// localStream.ringBufR.getNext() // TODO comment out this?

			cloneBuf := packet.bytes
			localStream.bytesChan <- cloneBuf // TODO buffer is sent over channel, need to copy?
			readSize = len(cloneBuf)
			log.Info().Msgf("%s sent to bytesChan", packet.String())

			if readSize == 0 && packet.streamId == TUNNEL_STREAM_ID_CTRL {
				mux.shouldEnd = true
			}
			break
		}

		if readSize == 0 {
			log.Debug().Msgf("read buffer's size is 0")
			if localStream != nil && len(localStream.syncChan) == 0 {
				localStream.syncChan <- true // when exiting, readLocalTransport() may be waiting, notify syncChan here
			}

			if mux.shouldEnd { // stream ends or read 0-size buffer
				log.Debug().Msgf("should end")
				mux.sendRelease()
				for _, workCiti := range session.localStreamMap { // shouldEnd all tunnel streams
					if len(workCiti.syncChan) == 0 {
						workCiti.syncChan <- true // when exiting, readLocalTransport() may be waiting, notify syncChan here
					}
				}
				break
			}
		}
	}

	reverseTunnelPreCloseHook(mux)
	log.Info().Int("sessionId", session.Id).Msgf("conn reader exits")
	mux.exitChan <- true
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

type VisionedTransport struct {
	transport *Transport
	revision  int
}

// session packetChan => conn
func writeTunnelTransportGR(mux *Mux) {
	session := mux.transport.Session
	sessionId := session.Id
	packetChan := session.packetChan
	if PRE_ENC {
		packetChan = session.packetEncChan
	}

	var visionedTransport VisionedTransport
	visionedTransport.revision, visionedTransport.transport = mux.getRevAndTransport() // initialized with mux revision

	// TODO enable this buffer optimization
	//var buffer bytes.Buffer

	//collectAndWriteLoop:
	for {
		log.Debug().Int("sessionId", sessionId).Msgf("waiting for packet from packetChan ...")
		packet := <-packetChan
		log.Debug().Int("sessionId", sessionId).Msgf("got packet from packetChan, %s", packet.String())

		//buffer.Reset()
		//// TODO buffer the first packet into `buffer`, so we can remove the last one-packet writing call
		//
		//bufferedPacketCount := 0
		//for len(packetChan) > 0 && packet.kind == PACKET_KIND_NORMAL { // there are more NORMAL packet, note if not going into the loop, pkt.bytes are not buffered
		//	log.Debug().Int("sessionId", sessionId).Msgf("buffer more packets")
		//	// packets are buffered, sent in batch
		//	if buffer.Len()+len(packet.bytes) > MAX_PACKET_SIZE {
		//		log.Debug().Int("sessionId", sessionId).Msgf("buffered %d packets, buffer size: %d", bufferedPacketCount, buffer.Len())
		//		break // cannot hold more, have to send now
		//	}
		//
		//	sentPkt := Packet{bytes: packet.bytes, kind: PACKET_KIND_NORMAL_DIRECT, streamId: packet.streamId}
		//	streamContinues, err := writePacketToWriter(&sentPkt, &buffer, visionedTransport.transport, true) // bytes written to buffer
		//	if err != nil {
		//		log.Fatal().Int("sessionId", sessionId).Err(err).Msgf("fail to write to conn")
		//	}
		//	if !streamContinues {
		//		break collectAndWriteLoop
		//	}
		//
		//	packet = <-packetChan // read more
		//	bufferedPacketCount += 1
		//}
		//
		//if buffer.Len() != 0 {
		//	// TODO this buffer is not sent as a packet! HOW does this work?
		//	log.Debug().Int("sessionId", sessionId).Msgf("write packets buffer, size: %d ...", buffer.Len())
		//	if _, err := visionedTransport.transport.Conn.Write(buffer.Bytes()); err != nil { // use transport to write bytes
		//		log.Err(err).Int("sessionId", sessionId).
		//			Msgf("tunnel batch writing failed, writeNo: %d", visionedTransport.transport.Session.WriteNo)
		//
		//		// Batch buffer is encrypted with the cipher before reconnect, so if sent as is, decryption fails on the receiving side.
		//		// To avoid that, if batch write fails, recover with rewrite without batch writing.
		//		if !reconnectAndRewrite(mux, &visionedTransport) { // fail to write to tunnel transport, reconnect and write
		//			break
		//		}
		//	}
		//}

		// in case packet is not buffer into `buffer`
		// TODO try to remove this call
		log.Debug().Int("sessionId", sessionId).Msgf("one packet / no buffer write, %s", packet.String())
		if !writePacketToTransportWithRetry(mux, &packet, &visionedTransport) { // write one packet
			break
		}
	}
	log.Info().Int("sessionId", sessionId).Msg("writing to conn ends")

	mux.exitChan <- true
}

// Write packet to connInfoRev.
//
// If writing fails, reconnect and resend.
// When resending, resolve the inconsistency with its ReadNo of the sending party, also resend data that has already been sent.
// When resending data that has already been sent, resend the data up to just before writeNo.
// Send data after writeNo using packet data.
// returns whether continues
func writePacketToTransportWithRetry(mux *Mux, pkt *Packet, connInfoRev *VisionedTransport) bool {
	session := connInfoRev.transport.Session
	for {
		log.Debug().Int("sessionId", session.Id).Msgf("to write bytes to conn, WriteNo: %d, pkt: %s", session.WriteNo, pkt.String())
		streamContinues, err := writePacketToWriter(pkt, connInfoRev.transport.Conn, connInfoRev.transport, true)
		if err == nil {
			log.Debug().Int("sessionId", session.Id).Msgf("pkt written, streamContinues: %t", streamContinues)
			return streamContinues
		}

		log.Err(err).Msgf("failed to write pkt to transport, writeNo: %d", session.WriteNo)
		if !reconnectAndRewrite(mux, connInfoRev) { // fail to write single packet to tunnel transport, reconnect and write
			log.Error().Int("sessionId", session.Id).Msgf("retry failed, writeNo: %d", session.WriteNo)
			return false
		}
		log.Debug().Int("sessionId", session.Id).Msgf("retry to write, writeNo: %d", session.WriteNo)
	}
}

func reconnectAndRewrite(mux *Mux, connInfoRev *VisionedTransport) bool {
	end := false
	connInfoRev.transport, connInfoRev.revision, end = mux.reconnect(connInfoRev.revision)
	if end {
		return false
	}
	if !rewrite2Tunnel(mux, connInfoRev) {
		return false
	}
	return true
}

// resend data to Tunnel
//
// @param info pipe info
// @param transport connection information
// @param revision revision
// @return bool true to continue processing
func rewrite2Tunnel(mux *Mux, connInfoRev *VisionedTransport) bool {
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
					connInfoRev.transport, connInfoRev.revision, end = mux.reconnect(connInfoRev.revision) // fail to write, reconnect
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
