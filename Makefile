build:
	@go build -o bin/netcalcsrv

run: build
	@./bin/netcalcsrv

test:
	@go test -v ./...
