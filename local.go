package main

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/rs/zerolog/log"
)

func acceptAndProcess(listenInfo ListenInfo, mux *pipeInfo) {
	log.Info().Msgf("waiting for %s ...", listenInfo.forwardInfo.String())
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

	log.Printf("Accepted, forward: %s", listenInfo.forwardInfo.String())

	citi := mux.connInfo.SessionInfo.addCiti(src, CITIID_CTRL)
	dest := listenInfo.forwardInfo.Dest

	{ // send conn signal to notify the other party
		connInfo := mux.connInfo

		var buffer bytes.Buffer
		buffer.Write([]byte{CTRL_HEADER})
		buf, _ := json.Marshal(&ConnHeader{dest, citi.citiId})
		buffer.Write(buf)
		connInfo.SessionInfo.packChan <- PackInfo{buffer.Bytes(), PACKET_KIND_NORMAL, CITIID_CTRL}
		log.Info().Msgf("conn control req sent")
	}

	log.Info().Msgf("waiting for conn control resp ...")
	respHeader := <-citi.respHeader
	if !respHeader.Result {
		log.Printf("failed to connect, dest: %s, conn control resp: %s", dest.String(), respHeader.Mess)
		return
	}

	go relaySession(mux, citi, dest)
	needClose = false
}

func acceptAndProcessInfinitely(listenInfo ListenInfo, info *pipeInfo) {
	for {
		acceptAndProcess(listenInfo, info)
	}
}

func localConnectOrAccept(isClient bool, listenGroup *ListenGroup, localForwardList []Forward, connInfo *ConnInfo, info *pipeInfo,
	dialer func(dst string) (io.ReadWriteCloser, error)) {
	for _, listenInfo := range listenGroup.list {
		go acceptAndProcessInfinitely(listenInfo, info)
	}

	if len(localForwardList) > 0 {
		for {
			connCtrlHeader := connInfo.SessionInfo.getHeader() // get new connection connCtrlHeader, initiate one
			if connCtrlHeader == nil {
				break
			}
			log.Info().Msgf("get control header %s, create new connection now", connCtrlHeader.String())
			go NewConnect(dialer, connCtrlHeader, info)
		}
	}

	if len(listenGroup.list) > 0 {
		log.Info().Msgf("waiting exit signals from listeners group ...")
		for {
			if !<-connInfo.SessionInfo.releaseChan {
				log.Info().Msgf("receive false from release channel")
				break
			}

			if !isClient {
				log.Printf("client side: %t, exit", isClient)
				break
			}
		}
	}
}

func ListenAndNewConnectWithDialer(isClient bool, listenGroup *ListenGroup, localForwards []Forward, connInfo *ConnInfo, param *TunnelParam,
	reconnect func(sessionInfo *SessionInfo) *ConnInfo, dialer func(dst string) (io.ReadWriteCloser, error)) {
	mux := startRelaySession(connInfo, param.keepAliveInterval, len(listenGroup.list) > 0, reconnect)
	localConnectOrAccept(isClient, listenGroup, localForwards, connInfo, mux, dialer)

	log.Printf("disconnected")
	connInfo.SessionInfo.SetState(Session_state_disconnected)
}
