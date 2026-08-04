# xfer
Command-line tool for data transfer over TCP/UDP

### Build and run
```
go test -v ./...
go test ./src/internal/helpers
go run src/main.go

go run  ./src/main.go

#linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o .bin/xfer ./src/main.go

#win
GOOS=windows GOARCH=amd64 go build -o .bin/xfer-windows-amd64.exe ./src/main.go

# Run server:
# One client, then exit after it disconnects
./.bin/xfer -l

# One client at a time; accept a replacement after disconnect
./.bin/xfer -l -k

# Many clients at once; terminal input broadcasts to all of them
./.bin/xfer -l -m

# Run client:
./.bin/xfer

# Show help:
./.bin/xfer -h



./.bin/xfer -l -s
./.bin/xfer -s

./.bin/xfer -l -s -key "secret"
./.bin/xfer -s -key "secret"

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
./.bin/xfer -l -tsl -cert cert.pem -key key.pem
./.bin/xfer -s -tls -cert cert.pem
```
