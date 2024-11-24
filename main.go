package main

import (
	"fmt"
	"time"

	"github.com/xxx/wscan/Plugins"
	"github.com/xxx/wscan/common"
)

func main() {
	start := time.Now()
	var Info common.HostInfo
	common.Flag(&Info)
	common.Parse(&Info)

	// if common.Iface != "" {
	// 	//添加环境变量 FORCEDIP
	// 	err := os.Setenv("FORCEDIP", common.Iface)
	// 	if err != nil {
	// 		fmt.Println("Failed to set environment variable FORCEDIP:", err)
	// 		return
	// 	}
	// 	// 尝试获取 FORCEDIP 环境变量
	// 	forcedIP := os.Getenv("FORCEDIP")
	// 	dllName := ""

	// 	fmt.Println("FORCEDIP:", forcedIP)

	// 	// 加载 BindIP  DLL
	// 	if runtime.GOARCH == "amd64" {
	// 		// 64位程序加载BindIP64.dll
	// 		dllName = "BindIP64.dll"
	// 	} else if runtime.GOARCH == "386" {
	// 		// 32位程序
	// 		dllName = "BindIP32.dll"
	// 	} else {
	// 		fmt.Println("Unknown architecture:", runtime.GOARCH)
	// 		fmt.Println("try ..")
	// 		dllName = "BindIP64.dll"
	// 	}

	// 	dllHandle, err := syscall.LoadLibrary(dllName)
	// 	if err != nil {
	// 		fmt.Println("Failed to load DLL:", err)
	// 		return
	// 	}
	// 	defer syscall.FreeLibrary(dllHandle)
	// }
	
	Plugins.Scan(Info)
	fmt.Printf("[*] scan done! cost: %s\n", time.Since(start))
}
