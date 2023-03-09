// -*- coding: utf-8 -*-
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/websocket"
)

func StartBotServer(serverInfo HostInfo) {
	server := serverInfo.String()
	log.Print("start echo --- ", server)
	local, err := net.Listen("tcp", server)
	if err != nil {
		log.Fatal().Err(err)
	}
	defer local.Close()
	for {
		conn, err := local.Accept()
		if err != nil {
			log.Fatal().Err(err)
		}
		log.Print("connected")
		bot := func() {
			for {
				if _, err := conn.Write([]byte("hello\n")); err != nil {
					break
				}
				time.Sleep(2 * time.Second)
			}
		}
		reader := func() {
			buf := make([]byte, 1000)
			for {
				if length, err := conn.Read(buf); err != nil {
					break
				} else {
					conn.Write([]byte(fmt.Sprintf("rep: %s", buf[:length])))
				}
			}
		}
		go bot()
		go reader()
	}
}

func StartEchoServer(serverInfo HostInfo) {
	server := serverInfo.String()
	log.Print("start echo --- ", server)
	local, err := net.Listen("tcp", server)
	if err != nil {
		log.Fatal().Err(err)
	}
	defer local.Close()
	for {
		conn, err := local.Accept()
		if err != nil {
			log.Fatal().Err(err)
		}
		log.Print("connected")
		go func(tunnel net.Conn) {
			defer tunnel.Close()
			io.Copy(tunnel, tunnel)
			log.Print("closed")
		}(conn)
	}
}

func StartHeavyClient(serverInfo HostInfo) {
	conn, err := net.Dial("tcp", serverInfo.String())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer conn.Close()

	dummy := make([]byte, 100)
	for index := 0; index < len(dummy); index++ {
		dummy[index] = byte(index)
	}
	log.Print("connected")

	prev := time.Now()
	writeCount := uint64(0)
	readCount := uint64(0)

	write := func() {
		for {
			if size, err := conn.Write(dummy); err != nil {
				log.Fatal().Err(err)
			} else {
				writeCount += uint64(size)
			}
		}
	}
	read := func() {
		for {
			if size, err := io.ReadFull(conn, dummy); err != nil {
				log.Fatal().Err(err)
			} else {
				readCount += uint64(size)
			}
			for index := 0; index < len(dummy); index++ {
				if dummy[index] != byte(index) {
					log.Fatal().Msgf("unmatch -- %d %d %X %X", readCount, index, dummy[index], byte(index))
				}
			}
		}
	}
	go write()
	go read()

	for {
		span := time.Now().Sub(prev)
		if span > time.Millisecond*1000 {
			prev = time.Now()
			log.Printf("hoge -- %d, %d", writeCount, readCount)
		}
	}
}

func processTcpServer(
	conn net.Conn, param *TunnelParam, forwardList []Forward,
	process func(*ConnInfo, *ListenGroup, []Forward)) {
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
	connInfo := CreateConnInfo(
		conn, tunnelParam.encPass, tunnelParam.encCount, nil, true)
	//newSession := false
	remoteAddrTxt := fmt.Sprintf("%s", conn.RemoteAddr())
	var retForwardList []Forward
	var err error
	if _, retForwardList, err = ProcessServerAuth(
		connInfo, &tunnelParam, remoteAddrTxt, forwardList); err != nil {
		connInfo.SessionInfo.SetState(Session_state_authmiss)

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
	process func(*ConnInfo, *ListenGroup, []Forward)) {
	conn, err := local.Accept()
	if err != nil {
		log.Fatal().Err(err)
	}

	go processTcpServer(conn, param, forwardList, process)
}

func StartServer(param *TunnelParam, forwardList []Forward) {
	log.Print("waiting --- ", param.serverInfo.String())
	local, err := net.Listen("tcp", param.serverInfo.String())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer local.Close()

	for {
		listenTcpServer(local, param, forwardList,
			func(connInfo *ConnInfo,
				listenGroup *ListenGroup, localForwardList []Forward) {
				ListenAndNewConnect(
					false, listenGroup, localForwardList,
					connInfo, param, GetSessionConn)
			})
	}
}

func StartReverseServer(param *TunnelParam, forwardList []Forward) {
	log.Print("waiting reverse --- ", param.serverInfo.String())
	local, err := net.Listen("tcp", param.serverInfo.String())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer local.Close()

	for {
		listenTcpServer(local, param, forwardList,
			func(connInfo *ConnInfo,
				listenGroup *ListenGroup, localForwardList []Forward) {
				ListenAndNewConnect(
					false, listenGroup, localForwardList,
					connInfo, param, GetSessionConn)
			})
	}
}

type WrapWSHandler struct {
	handle func(ws *websocket.Conn, remoteAddr string)
	param  *TunnelParam
}

// Http handler
func (handler WrapWSHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// Check connection source
	if err := AcceptClient(req.RemoteAddr, handler.param); err != nil {
		log.Printf("reject -- %s", err)
		w.WriteHeader(http.StatusNotAcceptable)
		//fmt.Fprintf( w, "%v\n", err )
		time.Sleep(3 * time.Second)
		return
	}
	defer ReleaseClient(req.RemoteAddr)

	log.Printf("accept websocket request %s", req.URL)

	wrap := func(ws *websocket.Conn) {
		// Run WrapWSHandler's handler
		handler.handle(ws, req.RemoteAddr)
	}

	// WebSocket server processing generation of Http Request.
	// Generate to run wrap.
	wshandler := websocket.Handler(wrap)
	// WebSocket server handle handling.
	wshandler.ServeHTTP(w, req)

	log.Printf("exit -- %v", req)
}

func execWebSocketServer(
	param TunnelParam, forwardList []Forward,
	connectSession func(*ConnInfo, *TunnelParam, *ListenGroup, []Forward)) {

	// Handler for WebSocket connection
	handle := func(ws *websocket.Conn, remoteAddr string) {
		// Set BinaryFrame because we are dealing with binary data
		ws.PayloadType = websocket.BinaryFrame

		connInfo := CreateConnInfo(ws, param.encPass, param.encCount, nil, true)
		if _, retForwardList, err := ProcessServerAuth(
			connInfo, &param, remoteAddr, forwardList); err != nil {
			connInfo.SessionInfo.SetState(Session_state_authmiss)
			log.Print("auth error: ", err)
			time.Sleep(3 * time.Second)
			return
		} else {
			listenGroup, localForwardList := NewListen(false, retForwardList)
			defer listenGroup.Close()

			connectSession(connInfo, &param, listenGroup, localForwardList)
		}
	}

	wrapHandler := WrapWSHandler{handle, &param}

	http.Handle("/", wrapHandler)
	err := http.ListenAndServe(param.serverInfo.String(), nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}

func StartWebsocketServer(param *TunnelParam, forwardList []Forward) {
	log.Print("start websocket -- ", param.serverInfo.String())

	execWebSocketServer(
		*param, forwardList,
		func(connInfo *ConnInfo, tunnelParam *TunnelParam,
			listenGroup *ListenGroup, localForwardList []Forward) {
			ListenAndNewConnect(
				false, listenGroup, localForwardList,
				connInfo, tunnelParam, GetSessionConn)
		})
}

func StartReverseWebSocketServer(param *TunnelParam, forwardList []Forward) {
	log.Print("start reverse websocket -- ", param.serverInfo.String())

	execWebSocketServer(
		*param, forwardList,
		func(connInfo *ConnInfo, tunnelParam *TunnelParam,
			listenGroup *ListenGroup, localForwardList []Forward) {
			ListenAndNewConnect(
				false, listenGroup, localForwardList,
				connInfo, tunnelParam, GetSessionConn)
		})
}
