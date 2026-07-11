# Bot-detector — build & run the honeypot (see docs/02, docs/12).
BD_ADDR ?= :8443

.PHONY: build test run dev vet clean fmt

build:            ## compile the honeypot server binary
	go build -o bin/honeypot ./honeypot/server

test:             ## run Go unit tests
	go test ./go/...

vet:
	go vet ./...

run: build        ## build + run (self-signed TLS on $BD_ADDR)
	BD_ADDR=$(BD_ADDR) ./bin/honeypot

dev:              ## run without a prebuilt binary
	BD_ADDR=$(BD_ADDR) go run ./honeypot/server

fmt:
	gofmt -w go honeypot

clean:
	rm -rf bin
