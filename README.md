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

xfer send [options] <source-file> <host:port>
xfer receive [options] <destination-file>
```

* With no host:port, the client connects to 127.0.0.1:9999
* With no port, the server uses port 9999

```sh
# Serve one client, then exit when it disconnects.
./.bin/xfer -l

# Keep listening. Permit one active client and reject additional clients.
./.bin/xfer -l -k

# Permit multiple simultaneous clients.
# Server-terminal input is broadcast to all connected clients.
./.bin/xfer -l -m

# Connect interactively.
./.bin/xfer example.com:9999
```

### Compression
Use -c to gzip-compress application data before it is passed to the selected secure transport. Compression capability negotiation occurs after TLS or custom transport setup.

## Custom Secure Transport
For authenticated encryption and man-in-the-middle protection, provide the same high-entropy pre-shared secret at both ends:
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
Generate a self-signed certificate:
```sh
openssl req -x509 -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost"
```

```sh
# Interactive TLS server and client.
./.bin/xfer -l -tls -cert cert.pem -key key.pem
./.bin/xfer -tls -cert cert.pem localhost:9999

# TLS file transfer.
./.bin/xfer receive -tls -cert cert.pem -key key.pem received.iso
./.bin/xfer send -tls -cert cert.pem source.iso localhost:9999
```

The client verifies the certificate chain and that its SAN matches the supplied hostname or IP address. For an IP address, generate the certificate with an IP SAN:
```sh
-addext "subjectAltName=IP:127.0.0.1"
```

## Redirects and pipeing
Standard input and output can  be redirected or piped in interactive mode:
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

### Receiving a File (interactive mode)
For one exact file transfer, start the server without `-k` or `-m` and
redirect its standard output to the destination file:
```sh
xfer -l > received.bin
# Send the file from the client:
./.bin/xfer server.example:9999 < input.bin
```

## File transfer
Receiver: listen on port 9999 and save the verified file.
```sh
./.bin/xfer receive received.iso
```

Sender: connect and send one file.
```sh
./.bin/xfer send source.iso receiver.example:9999
```

## Check whether a TCP port accepts connections.
```sh
./.bin/xfer -z example.com:443
```

## Options
```sh
-l              Listen in interactive server mode.
-k              Keep listening after an interactive client disconnects.
-m              Allow simultaneous interactive clients and broadcast server input.
-p port         Listen port or default interactive client port; default 9999.
-t seconds      I/O timeout; 0 disables it.
-s=true|false   Enable or disable custom ECDH/AES-GCM transport; default true.
-a secret       Pre-shared authentication secret for custom secure mode.
-tls            Use TLS 1.3 instead of custom secure mode.
-cert file      TLS server certificate, or client CA/server certificate to trust.
-key file       TLS server private key.
-c              Gzip-compress transferred data; both peers must enable it.
-z              Check whether a TCP port is reachable; no xfer protocol handshake.
-h              Show help.
```

# Todo

### Proxy support
Implement optional HTTP CONNECT proxy support for outbound xfer client connections.

Current project:
- Go module: github.com/jnsoft/xfer
- Entry point: src/main.go
- Client: src/internal/client/client.go
- Server: src/internal/server/server.go
- Admission protocol: src/internal/connection/admission.go
- Custom encrypted connection: src/internal/connection/secureconn.go

Important existing behavior:
- Client connects to one host:port target.
- client.RunClient currently uses net.Dial("tcp", target).
- client.CheckPort (used by -z) currently uses net.DialTimeout.
- After client TCP connection, it reads plaintext xfer admission:
  XFER/1 OK or XFER/1 BUSY.
- Then it optionally performs TLS 1.3 or custom ECDH/AES-GCM handshake.
- The server must NOT use a proxy. Proxy support applies only to outbound clients and -z checks.
- Existing custom secure mode is default. TLS is selected by -tls.
- -z checks raw TCP reachability only; it must not perform xfer admission, TLS, or custom secure handshake.

Goal:
- Honor HTTP_PROXY/http_proxy, HTTPS_PROXY/https_proxy, and NO_PROXY/no_proxy by default.
- Add CLI flags that can override those settings:
  -http-proxy
  -https-proxy
  -no-proxy
- CLI flags must override environment values only when explicitly provided.
  An omitted flag means use the environment.
  An explicit empty flag, for example -http-proxy="", means disable that proxy.
  Use a custom flag.Value or equivalent to track whether a flag was explicitly set.

Proxy behavior:
- Use HTTP CONNECT tunneling only.
- Plaintext and custom secure xfer connections use HTTP_PROXY.
- TLS xfer connections use HTTPS_PROXY.
- NO_PROXY must bypass proxy use for matching hostnames, domains, IPs, CIDRs, and localhost.
- Do not implement SOCKS, PAC, NTLM, or other proxy types in this change.
- Use golang.org/x/net/http/httpproxy for standard proxy environment and NO_PROXY matching instead of implementing matching manually.
- Add golang.org/x/net as a direct dependency if needed.

Implementation design:
1. Create a proxy-aware dialer in src/internal/client, preferably a new proxy.go file.
2. Refactor direct net.Dial and net.DialTimeout calls so normal client connections and CheckPort both use the same proxy-aware dial path.
3. Prefer a client Config struct over adding many positional parameters to RunClient.
4. The dialer should:
   - Resolve direct versus proxy use with httpproxy.Config.ProxyFunc().
   - Direct-dial target with timeout when no proxy applies.
   - For a proxy, dial the proxy address with timeout.
   - Send:
       CONNECT target-host:port HTTP/1.1
       Host: target-host:port
       Proxy-Connection: Keep-Alive
     followed by a blank line.
   - Support Basic proxy authentication if the proxy URL contains user:password.
   - Parse proxy response with HTTP parsing utilities.
   - Require HTTP 2xx status. For non-2xx, close the connection and return a clear error including the status; make 407 authentication errors obvious.
   - Clear temporary proxy handshake deadlines after successful CONNECT.
   - Return a net.Conn that represents the raw tunnel.
5. After successful CONNECT, existing xfer logic must continue unchanged: admission, TLS/custom handshake, then stdin/stdout copying.
6. A CONNECT-capable proxy does not need to understand xfer protocol. It only forwards bytes after responding 200.
7. If an HTTP proxy rejects CONNECT or blocks target port 9999, return a clear error; never silently fall back to direct connection.

Buffered response detail:
- If HTTP response parsing uses bufio.Reader, preserve any bytes already buffered after the CONNECT response.
- Implement a net.Conn wrapper that reads from the buffered reader first and then the underlying connection if needed.

Timeout behavior:
- Apply the configured timeout to dialing the proxy and the HTTP CONNECT exchange.
- Existing -z default is 5 seconds when -t is 0; preserve this.
- -z through a proxy verifies that a TCP CONNECT tunnel can be established. It does not verify target is an xfer server.

Required tests:
- Create fake local HTTP CONNECT proxy tests in src/internal/client.
- Verify direct dialing without proxy.
- Verify HTTP_PROXY routes connection through fake proxy.
- Verify -tls chooses HTTPS_PROXY.
- Verify NO_PROXY=127.0.0.1 bypasses proxy.
- Verify explicit CLI proxy override replaces environment proxy.
- Verify explicit empty override disables environment proxy.
- Verify CONNECT request target and Host header are target host:port.
- Verify proxy URL credentials produce Proxy-Authorization: Basic header.
- Verify 407 and other non-2xx proxy responses return useful errors.
- Verify CheckPort uses the proxy-aware dialer.
- Run go test ./..., go vet ./..., and go test -race ./....

Documentation:
- Update main.go usage and README.
- Document that proxy support is client-only and requires HTTP CONNECT.
- Mention HTTP_PROXY, HTTPS_PROXY, and NO_PROXY.
- State that some proxies only allow CONNECT to port 443 and may block xfer default port 9999.
- State that the proxy can see destination and traffic metadata; TLS/custom secure mode protects payload after CONNECT.
- For custom secure transport, recommend -a with a strong shared secret to protect against active MITM.

### Azure Blob Storage

Add optional Azure Blob Storage upload and download support.

Requirements:
- Client uploads a local file to Azure Blob Storage.
- Encrypt the file on the client before upload; Blob Storage must receive only ciphertext.
- Downloaded ciphertext is decrypted locally back into the original file.
- Use authenticated encryption, such as AES-256-GCM, with a fresh random nonce per encrypted file.
- Never store the encryption key in the blob, blob metadata, repository, logs, or command-line output.
- Define a safe key-management approach before implementation, such as a user-supplied key from stdin, environment variable, or OS secret store.
- Store required non-secret decryption metadata, such as format version and nonce, in a versioned binary file header or Azure blob metadata.
- Verify integrity during decryption and return a clear error if authentication fails.
- Support large files with streaming or chunked authenticated encryption; do not load whole files into memory.
- Add explicit upload/download commands or flags rather than mixing this behavior into normal TCP client mode.
- Use the official Azure SDK for Go and add unit tests for round-trip encryption/decryption plus integration tests against Azurite or a dedicated test storage account.




