BIN := xcfetch
PREFIX ?= /usr/local

.PHONY: build test vet fmt install clean nettest

build:
	go build -trimpath -o $(BIN) .

install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BIN) $(PREFIX)/bin/$(BIN)

test:
	go test ./...

# Network tests hit Apple's real endpoints.
nettest:
	XCFETCH_NET_TESTS=1 go test ./... -v

vet:
	go vet ./...

fmt:
	gofmt -l -w .

clean:
	rm -f $(BIN)
