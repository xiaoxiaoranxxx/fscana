:: go install github.com/goreleaser/goreleaser@latest
:: goreleaser build  --snapshot  --clean

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=386
go build -o fscanx32.exe -ldflags="-s -w"  -trimpath  main.go
upx -9 fscanx32.exe

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o fscanx.exe main.go
upx -9  fscanx.exe

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=386
go build -ldflags="-s -w" -trimpath -o fscanx_386 main.go
upx -9  fscanx_386

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o fscanx64 main.go
upx -9  fscanx64

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=arm
go build -ldflags="-s -w" -trimpath -o fscanx_arm main.go
upx -9  fscanx_arm

set CGO_ENABLED=0
set GOOS=linux
set GOARCH=mips
go build -ldflags="-s -w" -trimpath -o fscanx_mips main.go
upx -9  fscanx_mips

pause
