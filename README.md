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



# TODO

- [ ] add test cases for C/S 
- [ ] config file, normalize command options