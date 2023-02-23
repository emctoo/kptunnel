my tunnel server impl
=====================


# test commands

- websocket server

```shell
./wsd wsserver :1034 -pass 42 -encPass 42
```

- websocket client

```shell
./wsc wsclient 127.0.0.1:1034 :2022,127.0.0.1:2023 -pass 42 -encPass 42
```

- socat tcp echo client
```shell
socat - tcp4:127.0.0.1:2023,connect-timeout=1
```

- socat tcp echo server
```shell
socat tcp-l:2023,reuseaddr,fork exec:"/bin/cat"
```

- compile when code changes
```shell
watchexec -e go -- go build -o wsc cmd/websocket_client/main.go
```

```shell
watchexec -e go -- go build -o wsd cmd/websocket_server/main.go
```

- testing
```shell
watchexec -r -e go,py -- ./scripts/launch.py
```

# TODO

- [ ] add test cases for C/S 
- [ ] config file, normalize command options