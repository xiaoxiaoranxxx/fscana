:: go install github.com/goreleaser/goreleaser@latest
:: goreleaser build  --snapshot  --clean

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=386
go build -o bin/fscana32.exe -ldflags="-s -w"  -trimpath  main.go
upx -9 bin/fscana32.exe

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o bin/fscana.exe main.go
upx -9  bin/fscana.exe

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=386
go build -ldflags="-s -w" -trimpath -o bin/fscana_386 main.go
upx -9  bin/fscana_386

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o bin/fscana64 main.go
upx -9  bin/fscana64

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=arm
go build -ldflags="-s -w" -trimpath -o bin/fscana_arm main.go
upx -9  bin/fscana_arm

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=mips
go build -ldflags="-s -w" -trimpath -o bin/fscana_mips main.go
upx -9  bin/fscana_mips

pause
