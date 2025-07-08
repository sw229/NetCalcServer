build:
	@go build -o bin/net_calc_server

run: build
	@./bin/net_calc_server

test:
	@go test -v ./...
