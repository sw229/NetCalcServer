build:
	@go build -o bin/netcalcsrv ./cmd/netcalcsrv

run: build
	@./bin/netcalcsrv

test:
	@go test -v ./...
