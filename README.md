# xfer
Command-line tool for data transfer over TCP/UDP

### Build and run
```
go test -v ./...
go test ./src/helpers
go run src/main.go

go build -o .bin/xfer ./src/main.go
./.bin/xfer -h

./.bin/xfer -l
./.bin/xfer

./.bin/xfer -l -s
./.bin/xfer -s

./.bin/xfer -l -s -key "secret"
./.bin/xfer -s -key "secret"

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
./.bin/xfer -l -tsl -cert cert.pem -key key.pem
./.bin/xfer -s -tls -cert cert.pem
```
