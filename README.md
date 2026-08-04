# xfer
`xfer` is an interactive TCP terminal data-transfer tool. 
It supports plaintext TCP, a custom ECDH P-256 plus AES-256-GCM transport, and TLS 1.3.

## Run
```sh
go run  ./src/main.go
```

## Test
```sh
go test ./...
go vet ./...
go test -race ./...

go test ./src/internal/helpers
go test ./src/internal/connection
go test -v ./...

```

## Build
```sh
#linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o .bin/xfer ./src/main.go

#win
GOOS=windows GOARCH=amd64 go build -o .bin/xfer-windows-amd64.exe ./src/main.go
```

## Usage
```sh
xfer [options] [host:port]
xfer -l [options]
```

With no host:port, the client connects to 127.0.0.1:9999

```sh
# Serve one client, then exit when it disconnects.
./.bin/xfer -l

# Keep listening. Permit one active client and reject additional clients.
./.bin/xfer -l -k

# Permit multiple simultaneous clients.
# Server-terminal input is broadcast to all connected clients.
./.bin/xfer -l -m

# Start client.
./.bin/xfer
```
## Custom Secure Transport
For authenticated encryption and man-in-the-middle protection, provide the
same high-entropy pre-shared secret at both ends:
```sh
# server:
./.bin/xfer -l -a "a-long-random-secret"
# client:
./.bin/xfer -a "a-long-random-secret" example.com:9999
```

## Plain text mode (insecure)
Custom secure mode is enabled by default, but can be disabled with 
`-s=false` to use plaintext TCP
```sh
./.bin/xfer -l -s=false
./.bin/xfer -s=false example.com:9999
```

### TLS 1.3
Generate a self-signed certificate for localhost:
```sh
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
```
Run the TLS server:
```sh
./.bin/xfer -l -tls -cert cert.pem -key key.pem
```

Run the TLS client. It trusts cert.pem and validates that the certificate
matches localhost:
```sh
./.bin/xfer -tls -cert cert.pem localhost:9999
```

For an IP-address connection, the certificate needs an IP SAN instead when generating the certificate:
```sh
-addext "subjectAltName=IP:127.0.0.1"
```

Run the TLS client:
```sh
./.bin/xfer -tls -cert cert.pem 127.0.0.1:9999
```
## Redirects and pipeing
```sh
# client sends file:
./.bin/xfer < input.bin
cat input.bin | ./.bin/xfer 

#set server to inspect binary content:
./.bin/xfer -l | hexdump -C

./.bin/xfer server.example:9999 < input.bin > output.bin
cat input.bin | ./.bin/xfer server.example:9999 > output.bin
./.bin/xfer -l -m < input.bin > received.bin
```

### Receiving a File
For one exact file transfer, start the server without `-k` or `-m` and
redirect its standard output to the destination file:

```sh
xfer -l > received.bin
# Send the file from the client:
./.bin/xfer server.example:9999 < input.bin
```

## Check whether a TCP port accepts connections.
```sh
./.bin/xfer -z example.com:443
```

## Options
```sh
-l              Listen as a server.
-k              Keep listening after a client disconnects.
-m              Allow simultaneous clients; server input broadcasts to all.
-p port         Port to listen on or default client port; default 9999.
-t seconds      I/O timeout; 0 disables it.
-s=true|false   Enable or disable custom ECDH/AES-GCM transport; default true.
-a secret       Pre-shared authentication secret for custom secure mode.
-tls            Use TLS 1.3 instead of custom secure mode.
-cert file      TLS certificate on the server; trusted CA/server certificate on client.
-key file       TLS server private key.
-z              Check whether a TCP port is reachable; do not transfer data.
-h              Show help.
```
