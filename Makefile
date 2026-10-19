GO ?= go
LDFLAGS = -s -w

.PHONY: build windows test vet clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o drcom-linux-amd64 .

windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o drcom-windows-amd64.exe .

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

clean:
	rm -f drcom-linux-amd64 drcom-windows-amd64.exe
