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
```
