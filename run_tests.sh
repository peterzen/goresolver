
go test -coverprofile=coverage.out

go tool cover -func=coverage.out

golangci-lint run  --enable-all
