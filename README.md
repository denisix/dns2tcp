# dns2tcp
Simple forwarding+caching DNS server that works with upstreams over TCP

![GitHub](https://img.shields.io/github/license/denisix/dns2tcp.svg?style=flat-square)
![GitHub top language](https://img.shields.io/github/languages/top/denisix/dns2tcp.svg?style=flat-square)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/denisix/dns2tcp.svg?style=flat-square)

A tiny DNS server with the ability to forward your DNS requests to upper DNS servers using TCP proto:
* works like a transport proxy UDP -> TCP (requests coming to DNS server via UDP converts to queries over TCP)
* multi-threading (the main reason why golang used)
* cache-in-memory
* periodic garbage collector (removes outdated records by TTL)
* configuration file support


#### flow diagram
```plain

                                         dns 1
                                       /
DNS                                   /
clients ---UDP---> dns2tcp server---TCP--------> dns 2
                                      \
                                       \
                                        ...
                                          \ dns N
```

#### usage
```bash
cd /etc
git clone https://github.com/denisix/dns2tcp

cd dns2tcp
go run dns2tcp.go
```

#### configuration
- `bind 127.0.0.1:53` - instructs server to listed on IP 127.0.0.1, port 53
- `ns 1.1.1.1:53` - send TCP DNS queries to upstream at 1.1.1.1 (CloudFlare in this case)
- `ttl-absent 3600` - how long cache absent records, their TTL in secs
- `timeout 100` - 100 msec timeout to wait for reply
- `retry 30` - retries before we gen the content
- `gc-interval 1800` - 30 min (1800 sec) interval for garbage collector runs


#### building binary
```bash
go build dns2tcp.go
./dns2tcp
```
