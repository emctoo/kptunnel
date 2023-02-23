// -*- coding: utf-8 -*-
package kptunnel

import (
	"io"
	"net/http"
	"strings"

	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

// Echo the data received on the WebSocket.
func EchoServer(ws *websocket.Conn) {
	io.Copy(ws, ws)
}

// This example demonstrates a trivial echo server.
func StartWebsocketEchoServer() {
	http.Handle("/echo", websocket.Handler(EchoServer))
	err := http.ListenAndServe(":12345", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}

type proxyInfo struct {
	// UA の文字列
	userAgent string
	// proxy サーバの URL
	url *url.URL
	// 接続用の dialer
	dialer proxy.Dialer

	tlsConfig *tls.Config
}

// proxy 経由で addr に接続する
func (info *proxyInfo) Dial(network, addr string) (net.Conn, error) {
	log.Print(info.url.Host)
	conn, err := info.dialer.Dial("tcp", info.url.Host)
	if err != nil {
		return nil, err
	}

	host := addr
	tlsFlag := false
	if url, err := url.Parse(addr); err == nil {
		switch url.Scheme {
		case "ws":
			host = "http://" + url.Host
		case "wss":
			host = "https://" + url.Host
			tlsFlag = true
		}
	}

	sub := func() error {
		req, err := http.NewRequest("CONNECT", host, nil)
		if err != nil {
			return err
		}
		req.Close = false
		if info.url.User != nil {
			pass, _ := info.url.User.Password()
			auth := fmt.Sprintf("%s:%s", info.url.User.Username(), pass)
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			req.Header.Set("Proxy-Authorization", basicAuth)
		}
		req.Header.Set("User-Agent", info.userAgent)

		log.Print("proxy write")
		err = req.Write(conn)
		if err != nil {
			return err
		}
		log.Print("proxy wait the response")
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		log.Print("proxy read the response")
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("proxy error -- %d", resp.StatusCode)
		}
		return nil
	}
	if err := sub(); err != nil {
		conn.Close()
		return nil, err
	}

	if tlsFlag {
		return tls.Client(conn, info.tlsConfig), nil
	}
	return conn, nil
}

// ConnectWebSocket connects to the server
func ConnectWebSocket(websocketUrl, proxyHost, userAgent string, param *TunnelParam, sessionInfo *SessionInfo, forwardList []ForwardInfo) ([]ForwardInfo, ReconnectInfo) {
	log.Printf("got forwards: %v", forwardList)
	if param.Ctrl == CTRL_STOP {
		workUrl, _ := url.Parse(websocketUrl)
		if workUrl.RawQuery != "" {
			websocketUrl += "&"
		}
		websocketUrl += "mode=Disconnect"
	}
	conf, err := websocket.NewConfig(websocketUrl, "http://localhost")
	if err != nil {
		log.Print("NewConfig error", err)
		return nil, ReconnectInfo{nil, true, err}
	}
	for key, list := range param.WsReqHeader {
		for _, val := range list {
			conf.Header.Add(key, val)
		}
	}
	if strings.Index(websocketUrl, "wss") == 0 {
		// Skip tls verification for now
		conf.TlsConfig = &tls.Config{InsecureSkipVerify: true}
	}
	var websock *websocket.Conn
	if proxyHost != "" {
		// proxy のセッション確立
		url, _ := url.Parse(proxyHost)
		proxy := proxyInfo{userAgent, url, proxy.Direct, conf.TlsConfig}
		conn, err := proxy.Dial("", websocketUrl)
		if err != nil {
			log.Print(err)
			return nil, ReconnectInfo{nil, true, err}
		}
		// proxy セッション上に websocket 接続
		websock, err = websocket.NewClient(conf, conn)
		if err != nil {
			log.Print("websocket error", websock, err)
			return nil, ReconnectInfo{nil, true, err}
		}
		//return websock, nil
	} else {
		websock, err = websocket.DialConfig(conf)
		if err != nil {
			log.Err(err).Msgf("websocket fail to dial")
			return nil, ReconnectInfo{nil, true, err}
		}
	}
	log.Info().Msgf("connected to %s", websocketUrl)

	websock.PayloadType = websocket.BinaryFrame // Settings for handling websocket transmission data as binary

	connInfo := CreateConnInfo(websock, param.EncPass, param.EncCount, sessionInfo, false)

	overrideForwardList := forwardList
	cont := true
	log.Printf("client is to auth, forwards: %v", forwardList)
	overrideForwardList, cont, err = ProcessClientAuth(connInfo, param, forwardList)
	if err != nil {
		log.Err(err).Msg("client failed to auth")
		connInfo.SessionInfo.SetState(Session_state_authmiss)
		_ = websock.Close()
		return nil, ReconnectInfo{nil, cont, err}
	}

	log.Printf("local forwards %v, from remote forwards: %v", forwardList, overrideForwardList)
	if overrideForwardList == nil || len(overrideForwardList) == 0 {
		overrideForwardList = forwardList
	}
	return overrideForwardList, ReconnectInfo{connInfo, true, nil}
}
