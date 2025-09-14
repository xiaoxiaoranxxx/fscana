package Plugins

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xxx/wscan/WebScan/lib"
	"github.com/xxx/wscan/common"
	"github.com/xxx/wscan/mylib/appfinger"
	"github.com/xxx/wscan/mylib/gonmap"
)

func init() {
	for _, port := range common.PORTList {
		common.ProtocolArray = append(common.ProtocolArray, strconv.Itoa(port))
	}
}

// 从标准输入读取 ip:port 并探测
func ScanFromStdin() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[ERROR] ScanFromStdin Scan panic: %v\n", r)
		}
	}()
	InitKscan()
	scanner := bufio.NewScanner(os.Stdin)
	addrChan := make(chan Addr, common.PortScanThreads)
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	common.LogSuccess(fmt.Sprintf("===================new task===================\n%s\nargs: %s\ntarget: stdin", nowStr, strings.Join(os.Args[1:], " ")))
	fmt.Println("start infoscan")
	lib.Inithttp()

	go func() {
		PortScanFromChan(addrChan)
	}()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		//parts := strings.Split(line, ":")
		//if len(parts) != 2 {
		//	fmt.Fprintf(os.Stderr, "[!] 输入格式错误: %s\n", line)
		//	continue
		//}
		ip, port := "", ""
		re := regexp.MustCompile(`^.*?(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}).*?$`)
		//Discovered open port 8000/tcp on 222.213.125.131
		re_masscan := regexp.MustCompile(`^Discovered.*port\s+(\d{1,5}).*on\s+(\d{1,3}(?:\.\d{1,3}){3}).*$`)
		matches := re.FindAllStringSubmatch(line, -1)
		matches_masscan := re_masscan.FindAllStringSubmatch(line, -1)
		if len(matches) >= 1 {
			match := matches[0]
			if len(match) == 3 {
				ip = match[1]
				port = match[2]
			} else {
				continue
			}

		} else if len(matches_masscan) >= 1 {
			match := matches_masscan[0]
			if len(match) == 3 {
				port = match[1]
				ip = match[2]
			} else {
				continue
			}
		} else {
			continue
		}

		info := common.HostInfo{Host: ip, Ports: port}
		portInt, err := strconv.Atoi(info.Ports)
		if err != nil {
			portInt = 80
		}
		addrChan <- Addr{info.Host, portInt}

	}
	close(addrChan)
	common.LogWG.Wait()

	alivePortReport := "[+] alive ports(%d): "
	count := 0
	common.AlivePort.Range(func(key, value interface{}) bool {
		alivePort := key.(int)
		alivePortReport += strconv.Itoa(alivePort)
		alivePortReport += ","
		count++
		return true
	})
	alivePortReport = fmt.Sprintf(alivePortReport, count)
	alivePortReport = strings.TrimRight(alivePortReport, ",")
	common.LogSuccess(alivePortReport)
	common.LogWG.Wait()
	close(common.Results)
}

//go:embed fingerprint.txt
var fingerprintEmbed embed.FS

const (
	fingerprintPath = "fingerprint.txt"
)

type PortInfo struct {
	*gonmap.Response
	ip   string
	port string
}

func InitKscan() {
	//HTTP指纹库初始化
	if _, err := os.Stat("fingerprint.txt"); err == nil {
		fs, err := os.Open("fingerprint.txt")
		if err != nil {
			fmt.Println("[-] open fingerprint.txt error:", err)
			return
		}
		defer fs.Close()
		if n, err := appfinger.InitDatabaseFS(fs); err != nil {
			fmt.Println("load fingerprint file1 error, check static/fingerprint.txt file,", err)
		} else {
			fmt.Printf("load web fingerprint success :[%d] \n", n)
		}
	} else {
		fmt.Println("load web fingerprint fail.. trying with embed db now..")
		fs, err := fingerprintEmbed.Open(fingerprintPath)
		if err != nil {
			fmt.Println("[debug] embed err: ", err)
		}
		if n, err := appfinger.InitDatabaseFS(fs); err != nil {
			fmt.Println("load fingerprint file2 error, check static/fingerprint.txt file,", err)
		} else {
			fmt.Printf("load web fingerprint success :[%d] \n", n)
		}
	}

}

func Scan(info common.HostInfo) {
	if appfinger.Db_init_ok == false {
		InitKscan()
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[ERROR] Goroutine Scan panic: %v\n", r)
		}
	}()

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	common.LogSuccess(fmt.Sprintf("===================new task===================\n%s\nargs: %s\ntarget: %s", nowStr, strings.Join(os.Args[1:], " "), info.Host))

	fmt.Println("start infoscan")
	Hosts, err := common.ParseIP(info.Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		return
	}
	lib.Inithttp()
	var wg = sync.WaitGroup{}
	web := strconv.Itoa(common.PORTList["web"])
	ms17010 := strconv.Itoa(common.PORTList["ms17010"])
	if len(Hosts) > 0 || len(common.HostPort) > 0 {
		if common.NoPing == false && len(Hosts) > 1 || common.Scantype == "icmp" {
			Hosts = CheckLive(Hosts, common.Ping)
			fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
		}
		if common.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}
		var AlivePortInfo []*PortInfo
		if common.Scantype == "webonly" || common.Scantype == "webpoc" {
			AlivePortInfo = NoPortScan(Hosts, common.Ports)
		} else if common.Scantype == "hostname" {
			common.Ports = "139"
			AlivePortInfo = NoPortScan(Hosts, common.Ports)
		} else if len(Hosts) > 0 {
			AlivePortInfo = PortScan(Hosts, common.Ports, common.TcpTimeout)
			fmt.Println("[*] alive ports len is:", len(AlivePortInfo))
			if common.Scantype == "portscan" {
				common.LogWG.Wait()
				return
			}
		}
		if len(common.HostPort) > 0 {
			//AlivePortInfo = append(AlivePortInfo, common.HostPort...)
			//AlivePortInfo = common.RemoveDuplicate(AlivePortInfo)
			//common.HostPort = nil
			//fmt.Println("[*] AlivePort len is:", len(AlivePortInfo))
		}
		var severports []string //severports := []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
		for _, port := range common.PORTList {
			severports = append(severports, strconv.Itoa(port))
		}
		fmt.Println("start vulscan")
		fmt.Println("===============================")
		for _, portInfo := range AlivePortInfo {
			//fmt.Println("[debug] get portInfo:", portInfo)
			//ipPortSlice := strings.Split(portInfo, ":")
			//if len(ipPortSlice) < 2 {
			//	fmt.Println("err: scanner get wrong format host =", portInfo)
			//	continue
			//}
			info.Host = portInfo.ip
			info.Ports = portInfo.port
			protocol := ""
			//certInfo := ""
			banner := ""
			if portInfo.Response != nil {
				protocol = portInfo.FingerPrint.Service
				if protocol == "" {
					protocol = "unkown"
				}
				//certInfo = portInfo.FingerPrint.Info
				banner = portInfo.Raw
			}

			//fmt.Println("[debug] get cert:", certInfo)
			//if strings.Contains(info.Ports, "_") {
			//	slice := strings.Split(info.Ports, "_")
			//	if len(slice) > 0 {
			//		info.Ports = slice[0]
			//		if len(slice) >= 2 {
			//			protocol = slice[1]
			//			if len(slice) == 3 {
			//				banner = slice[2]
			//			} else {
			//				banner = strings.Join(slice[2:], "_")
			//			}
			//		}
			//	}
			//}

			switch {
			case info.Ports == "135":
				AddScan(info.Ports, info, &wg) //findnet
				if common.IsWmi {
					AddScan("1000005", info, &wg) //wmiexec
				}
			case info.Ports == "389":
				res := fmt.Sprintf("[+] Product %s://%s:%s\tbanner\t(%s)", protocol, info.Host, info.Ports, "[+]DC")
				common.LogSuccess(res)
			case info.Ports == "445":
				AddScan(ms17010, info, &wg)    //ms17010
				AddScan(info.Ports, info, &wg) //smb
				//AddScan("1000002", info, ch, &wg) //smbghost
			case info.Ports == "9000":
				//AddScan(web, info, &wg)        //http
				AddScan(info.Ports, info, &wg) //fcgiscan
			case IsContain(severports, info.Ports):
				//fmt.Println("[debug] current port =", info.Ports)
				AddScan(info.Ports, info, &wg) //plugins scan
				fallthrough                    // 继续执行下一个分支
			default:
				if common.UseNmap {
					//fmt.Println("get protocol:", protocol, len(protocol))
					if strings.Contains(protocol, "http") {
						AddScan(web, info, &wg) //webtitle
					} else if protocol == "imap" || protocol == "imap-proxy" || protocol == "smtp" || protocol == "pop3" || protocol == "ssh" || protocol == "ftp" {
						banner = strings.ReplaceAll(banner, "\r\n", "__")
						banner = strings.ReplaceAll(banner, "\n", "__")
						banner = strings.ReplaceAll(banner, "\r", "__")
						if strings.HasSuffix(banner, "__") {
							banner = banner[:len(banner)-2]
						}
						if (protocol == "ssh" || strings.HasPrefix(protocol, "imap")) && len(banner) >= 70 {
							banner = banner[:70]
							banner = strings.Split(banner, "__")[0]
						}

						res := fmt.Sprintf("[+] Product %s://%s:%s\tbanner\t(%s)", protocol, info.Host, info.Ports, banner)
						common.LogSuccess(res)
					} else if protocol == "rdp" && info.Ports != "3389" {
						AddScan("3389", info, &wg)
					}
				} else {
					AddScan(web, info, &wg) //webtitle
				}

			}
			//portInfo = nil
		}
	}
	for _, url := range common.Urls {
		info.Url = url
		AddScan(web, info, &wg)
	}
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	fmt.Printf("\n[*] ok: %v/%v\n", common.End, common.Num)
}

var Mutex = &sync.Mutex{}

func AddScan(scantype string, info common.HostInfo, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer func() {
			Mutex.Lock()
			common.End += 1
			Mutex.Unlock()
			wg.Done()
			if r := recover(); r != nil {
				fmt.Printf("[ERROR] Goroutine AddScan panic: %v\n", r)
			}
		}()
		Mutex.Lock()
		common.Num += 1
		Mutex.Unlock()
		ScanFunc(&scantype, &info)
	}()
}

func ScanFunc(name *string, info *common.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[-] %v:%v scan error: %v\n", info.Host, info.Ports, err)
		}
	}()
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
