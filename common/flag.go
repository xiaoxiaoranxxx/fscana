package common

import (
	"flag"
	"fmt"
	"github.com/xxx/wscan/mylib/grdp/login"
	"os"
	"time"
)

func Banner() {
	banner := `
$$$$$$$$\                                         $$$$$$\ $$\     
$$  _____|                                        \_$$  _|$$ |    
$$ |      $$$$$$$\  $$\  $$$$$$\  $$\   $$\         $$ |$$$$$$\   
$$$$$\    $$  __$$\ \__|$$  __$$\ $$ |  $$ |        $$ |\_$$  _|  
$$  __|   $$ |  $$ |$$\ $$ /  $$ |$$ |  $$ |        $$ |  $$ |    
$$ |      $$ |  $$ |$$ |$$ |  $$ |$$ |  $$ |        $$ |  $$ |$$\ 
$$$$$$$$\ $$ |  $$ |$$ |\$$$$$$  |\$$$$$$$ |      $$$$$$\ \$$$$  |
\________|\__|  \__|$$ | \______/  \____$$ |      \______| \____/ 
              $$\   $$ |          $$\   $$ |                      
              \$$$$$$  |          \$$$$$$  |                      
               \______/            \______/                                             
` + version + `
`
	print(banner)
}

func Flag(Info *HostInfo) {
	Banner()
	flag.StringVar(&Info.Host, "h", "", "IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&NoHosts, "hn", "", "the hosts no scan,as: -hn 192.168.1.1/24")
	flag.StringVar(&Ports, "p", DefaultPorts, "Select a port,for example: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&PortAdd, "pa", "", "add port base DefaultPorts,-pa 3389")
	flag.StringVar(&UserAdd, "usera", "", "add a user base DefaultUsers,-usera user")
	flag.StringVar(&PassAdd, "pwda", "", "add a password base DefaultPasses,-pwda password")
	flag.StringVar(&NoPorts, "pn", "", "the ports no scan,as: -pn 445")
	flag.StringVar(&Command, "c", "", "exec command (ssh|wmiexec)")
	flag.StringVar(&SshKey, "sshkey", "", "sshkey file (id_rsa)")
	flag.StringVar(&Domain, "domain", "", "smb domain")
	flag.StringVar(&Username, "user", "", "username")
	flag.StringVar(&Password, "pwd", "", "password")
	flag.Int64Var(&TcpTimeout, "time", 8, "Set timeout")
	flag.StringVar(&Scantype, "m", "all", "Select scan type ,as: -m ssh")
	flag.StringVar(&Path, "path", "", "fcgi、smb romote file path")
	flag.IntVar(&PortScanThreads, "t", 1024, "Port scan Thread nums")
	flag.IntVar(&LiveTop, "top", 10, "show live len top")
	flag.StringVar(&HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&Userfile, "userf", "", "username file")
	flag.StringVar(&Passfile, "pwdf", "", "password file")
	flag.StringVar(&PortFile, "portf", "", "Port File")
	flag.StringVar(&PocPath, "pocpath", "", "poc file path")
	flag.StringVar(&RedisFile, "rf", "", "redis file to write sshkey file (as: -rf id_rsa.pub)")
	flag.StringVar(&RedisShell, "rs", "", "redis shell to write cron file (as: -rs 192.168.1.1:6666)")
	flag.BoolVar(&NoPoc, "nopoc", false, "not to scan web vul")
	flag.BoolVar(&NoBrute, "nobr", false, "not to Brute password")
	flag.IntVar(&BruteThread, "br", 15, "Brute threads")
	flag.BoolVar(&NoPing, "np", false, "not to ping")
	flag.BoolVar(&Ping, "ping", false, "using ping replace icmp")
	flag.StringVar(&Outputfile, "o", "result.txt", "Outputfile")
	flag.BoolVar(&TmpSave, "no", false, "not to save output log")
	flag.Int64Var(&WaitTime, "debug", 60, "every time to LogErr")
	flag.BoolVar(&Silent, "silent", false, "silent scan")
	flag.BoolVar(&Nocolor, "nocolor", false, "no color")
	flag.BoolVar(&PocFull, "full", false, "poc full scan,as: shiro 100 key")
	flag.StringVar(&URL, "u", "", "url")
	flag.StringVar(&UrlFile, "uf", "", "urlfile")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, -pocname weblogic")
	flag.StringVar(&Proxy, "proxy", "", "set poc proxy, -proxy http://127.0.0.1:8080")
	flag.StringVar(&Socks5Proxy, "socks5", "", "set socks5 proxy, will be used in tcp connection, timeout setting will not work")
	flag.StringVar(&Cookie, "cookie", "", "set poc cookie,-cookie rememberMe=login")
	flag.Int64Var(&WebTimeout, "wt", 8, "Set web timeout")
	flag.BoolVar(&DnsLog, "dns", false, "using dnslog poc")
	flag.IntVar(&PocNum, "num", 20, "poc rate")
	flag.StringVar(&SC, "sc", "", "ms17 shellcode,as -sc add")
	flag.BoolVar(&IsWmi, "wmi", false, "start wmi")
	flag.StringVar(&Hash, "hash", "", "hash")
	flag.BoolVar(&Noredistest, "noredis", false, "no redis sec test")
	flag.BoolVar(&JsonOutput, "json", false, "json output")
	flag.BoolVar(&UseNmap, "nmap", false, "using gonmap to check protocol")      //own add
	flag.StringVar(&Iface, "iface", "", "local ip of iface want to use")         //own add
	flag.Float64Var(&PingRate, "prate", 0.1, "rate for icmp scan")               //own add
	flag.IntVar(&PingTimeout, "pt", 6, "ping timeout")                           //own add
	flag.IntVar(&TitleScanThreads, "tn", 60, "Title scan Thread nums")           //own add
	flag.BoolVar(&IsScreenShot, "screen", false, "make and save rdp screenshot") //own add

	flag.Parse()
	Title_scan_ch = make(chan int, TitleScanThreads)
	if IsScreenShot {
		nowTimestamp := time.Now().Format("2006_01_02_15_04_05")
		login.OutputDir = "img/" + nowTimestamp
		if _, err := os.Stat(login.OutputDir); os.IsNotExist(err) {
			mkdirErr := os.MkdirAll(login.OutputDir, 0755)
			if mkdirErr != nil {
				fmt.Println("Can not create rdp screenshot output dir:", mkdirErr)
			}
		}
	}
}
