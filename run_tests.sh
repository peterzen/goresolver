
go test -coverprofile=coverage.out

go tool cover -func=coverage.out | tee coverage.txt

golangci-lint run  --enable-all
