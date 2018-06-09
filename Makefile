build:
	GOPATH=$$PWD go build

get:
	GOPATH=$$PWD go get

clean:
	rm -f dnsserver

clean-all: clean
	rm -rf src

