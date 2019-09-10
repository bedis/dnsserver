build:
	go build

get:
	go get

clean:
	rm -f dnsserver

clean-all: clean
	rm -rf src

