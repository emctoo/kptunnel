// -*- coding: utf-8 -*-
package kptunnel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/websocket"
)

func processTcpServer(conn net.Conn, param *TunnelParam, forwardList []Forward, process func(*Transport, *ListenerGroup, []Forward)) {
	defer conn.Close()

	remoteAddr := fmt.Sprintf("%s", conn.RemoteAddr())
	log.Print("connected -- ", remoteAddr)
	if err := AcceptClient(remoteAddr, param); err != nil {
		log.Printf("unmatch ip -- %s", remoteAddr)
		time.Sleep(3 * time.Second)
		return
	}
	defer ReleaseClient(remoteAddr)

	tunnelParam := *param
	connInfo := newTransport(conn, tunnelParam.EncPass, tunnelParam.EncCount, nil, true)
	//newSession := false
	remoteAddrTxt := fmt.Sprintf("%s", conn.RemoteAddr())
	var retForwardList []Forward
	var err error
	if _, retForwardList, err = handleAuthOnServerSide(
		connInfo, &tunnelParam, remoteAddrTxt, forwardList); err != nil {
		connInfo.Session.SetState(Session_state_authmiss)

		log.Print("auth error: ", err)
		time.Sleep(3 * time.Second)
	} else {
		listenGroup, localForwardList := NewListen(false, retForwardList)
		defer listenGroup.Close()

		//log.Print("process")
		process(connInfo, listenGroup, localForwardList)
	}
}

func listenTcpServer(
	local net.Listener, param *TunnelParam, forwardList []Forward,
	process func(*Transport, *ListenerGroup, []Forward)) {
	conn, err := local.Accept()
	if err != nil {
		log.Fatal().Err(err)
	}

	go processTcpServer(conn, param, forwardList, process)
}

func StartServer(param *TunnelParam, forwardList []Forward) {
	log.Print("waiting --- ", param.ServerInfo.String())
	local, err := net.Listen("tcp", param.ServerInfo.String())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer local.Close()

	for {
		listenTcpServer(local, param, forwardList, func(connInfo *Transport,
			listenGroup *ListenerGroup, localForwardList []Forward) {
			ListenAndNewConnect(false, listenGroup, localForwardList, connInfo, param, getSessionTransport)
		})
	}
}

func StartReverseServer(param *TunnelParam, forwardList []Forward) {
	log.Print("waiting reverse --- ", param.ServerInfo.String())
	local, err := net.Listen("tcp", param.ServerInfo.String())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer local.Close()

	for {
		listenTcpServer(local, param, forwardList, func(connInfo *Transport, listenGroup *ListenerGroup, localForwardList []Forward) {
			ListenAndNewConnect(false, listenGroup, localForwardList, connInfo, param, getSessionTransport)
		})
	}
}

type WrapWSHandler struct {
	handle func(ws *websocket.Conn, remoteAddr string)
	param  *TunnelParam
}

// Http ハンドラ
func (handler WrapWSHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := AcceptClient(req.RemoteAddr, handler.param); err != nil {
		log.Printf("reject websocket connection, %s", err)
		w.WriteHeader(http.StatusNotAcceptable)
		time.Sleep(3 * time.Second)
		return
	}
	defer ReleaseClient(req.RemoteAddr)

	log.Info().Msgf("serving on %s ...", req.URL)

	wrap := func(ws *websocket.Conn) {
		// WrapWSHandler のハンドラを実行する
		handler.handle(ws, req.RemoteAddr)
	}

	// Http Request の WebSocket サーバ処理生成。
	// wrap を実行するように生成する。
	wshandler := websocket.Handler(wrap)
	// WebSocket サーバハンドル処理。
	wshandler.ServeHTTP(w, req)

	log.Printf("serving of %s ends", req.URL)
}

type WebSocketServer struct {
	server      *http.Server
	isReadyChan chan bool // send to this when the server is ready
	quitChan    chan bool // wait this
}

func (s *WebSocketServer) Stop(ctx context.Context) {
	_ = s.server.Shutdown(ctx)
}

func execWebSocketServer(param TunnelParam, forwardList []Forward, connectSession func(*Transport, *TunnelParam, *ListenerGroup, []Forward)) *http.Server {
	handle := func(ws *websocket.Conn, remoteAddr string) {
		ws.PayloadType = websocket.BinaryFrame // Set BinaryFrame because we are dealing with binary data

		connInfo := newTransport(ws, param.EncPass, param.EncCount, nil, true)
		_, retForwardList, err := handleAuthOnServerSide(connInfo, &param, remoteAddr, forwardList)
		if err != nil {
			connInfo.Session.SetState(Session_state_authmiss)
			log.Err(err).Msgf("server auth process failed, retry in 1 second(s)")
			time.Sleep(1 * time.Second)
			return
		}

		listenGroup, localForwardList := NewListen(false, retForwardList)
		defer listenGroup.Close()
		connectSession(connInfo, &param, listenGroup, localForwardList)
	}

	http.Handle("/", WrapWSHandler{handle, &param})
	log.Info().Msgf("server: %#v", param.ServerInfo)
	return &http.Server{Addr: param.ServerInfo.String()}
	//err := http.ListenAndServe(param.ServerInfo.String(), nil)
	//if err != nil {
	//	panic("ListenAndServe: " + err.Error())
	//}
}

func StartWebsocketServer(param *TunnelParam, forwardList []Forward) *http.Server {
	return execWebSocketServer(*param, forwardList, func(connInfo *Transport, tunnelParam *TunnelParam, listenGroup *ListenerGroup, localForwardList []Forward) {
		ListenAndNewConnect(false, listenGroup, localForwardList, connInfo, tunnelParam, getSessionTransport)
	})
}

// StartReverseWebSocketServer create a websocket server
func StartReverseWebSocketServer(param *TunnelParam, forwardList []Forward) *http.Server {
	return execWebSocketServer(*param, forwardList, func(connInfo *Transport, tunnelParam *TunnelParam, listenGroup *ListenerGroup, localForwardList []Forward) {
		ListenAndNewConnect(false, listenGroup, localForwardList, connInfo, tunnelParam, getSessionTransport)
	})
}
