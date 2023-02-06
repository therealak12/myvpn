.PHONY: tidy vendor

tidy:
	go mod tidy

vendor:
	go mod tidy
	go mod vendor