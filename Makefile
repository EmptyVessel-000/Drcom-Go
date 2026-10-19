GO ?= go
LDFLAGS = -s -w

.PHONY: build windows test vet clean

build:
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/drcom-linux-amd64 .

windows:
	mkdir -p dist
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/drcom-windows-amd64.exe .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -rf dist
	rm -f drcom-linux-amd64 drcom-windows-amd64.exe
