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
	Plugins.Scan(Info)
	fmt.Printf("[*] scan done! cost: %s\n", time.Since(start))
}
