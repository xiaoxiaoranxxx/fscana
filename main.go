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

	// 检查是否有 --std 参数（通过flag）
	if common.StdInput {
		Plugins.ScanFromStdin()
		fmt.Printf("[*] scan done! cost: %s\n", time.Since(start))
		return
	}

	Plugins.Scan(Info)
	fmt.Printf("[*] scan done! cost: %s\n", time.Since(start))
}
