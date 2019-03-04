
golangci-lint run  --enable-all

go test -coverprofile=coverage.out

go tool cover -func=coverage.out
