package Plugins

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xxx/wscan/common"
	"golang.org/x/net/icmp"
)

var (
	AliveHosts []string
	ExistHosts = make(map[string]struct{})
	livewg     sync.WaitGroup
)

func CheckLive(hostslist []string, Ping bool) []string {
	// fmt.Printf("MaxRate=%f, Bucket_limit=%d, PacketTime=%v\n", common.MaxRate, common.Bucket_limit, common.PacketTime)
	chanHosts := make(chan string, len(hostslist))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("[ERROR] Goroutine CheckLive panic: ", r)
			}
		}()
		for ip := range chanHosts {
			if _, ok := ExistHosts[ip]; !ok && IsContain(hostslist, ip) {
				ExistHosts[ip] = struct{}{}
				if common.Silent == false {
					if Ping == false {
						fmt.Printf("(icmp) Target %-15s is alive\n", ip)
					} else {
						fmt.Printf("(ping) Target %-15s is alive\n", ip)
					}
				}
				AliveHosts = append(AliveHosts, ip)
			}
			livewg.Done()
		}
	}()

	if Ping == true {
		//使用ping探测
		RunPing(hostslist, chanHosts)
	} else {
		//优先尝试监听本地icmp,批量探测
		var local_ip string = "0.0.0.0"
		if common.Iface != "" {
			local_ip = common.Iface
		}
		conn, err := icmp.ListenPacket("ip4:icmp", local_ip)
		if err == nil {
			RunIcmp1(hostslist, conn, chanHosts)
		} else {
			common.LogError(err)
			//尝试无监听icmp探测
			fmt.Println("trying RunIcmp2")
			conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", time.Duration(common.PingTimeout)*time.Second)
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			if err == nil {
				RunIcmp2(hostslist, chanHosts)
			} else {
				common.LogError(err)
				//使用ping探测
				fmt.Println("The current user permissions unable to send icmp packets")
				fmt.Println("start ping")
				RunPing(hostslist, chanHosts)
			}
		}
	}

	livewg.Wait()
	close(chanHosts)

	ArrayCountValueTop(AliveHosts, common.LiveTop)

	return AliveHosts
}

func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endflag := false
	go func() {
		for {
			if endflag == true {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, _ := conn.ReadFrom(msg)
			if sourceIP != nil {
				livewg.Add(1)
				chanHosts <- sourceIP.String()
			}
		}
	}()

	for _, host := range hostslist {
		common.Limiter.Wait(1) // 阻塞等待令牌桶中至少存在1个令牌,若存在则消耗掉1个令牌
		dst, _ := net.ResolveIPAddr("ip", host)
		IcmpByte := makemsg(host)
		conn.WriteTo(IcmpByte, dst)
	}

	//根据hosts数量修改icmp监听时间
	var wait time.Duration
	switch {
	case len(hostslist) <= 256:
		wait = time.Duration(common.PingTimeout) * time.Second
	default:
		wait = time.Duration(common.PingTimeout*2) * time.Second
	}

	start := time.Now()
	for {
		since := time.Since(start)
		if since > wait {
			break
		} else {
			time.Sleep(time.Duration(1))
		}
	}
	endflag = true
	conn.Close()
}

func RunIcmp2(hostslist []string, chanHosts chan string) {
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			common.Limiter.Wait(1) // 阻塞等待令牌桶中至少存在1个令牌,若存在则消耗掉1个令牌
			if icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

func icmpalive(host string) bool {
	startTime := time.Now()

	// 使用net.DialIP发送ICMP包，并设置本地地址
	local_ip := &net.IPAddr{
		IP: net.ParseIP("0.0.0.0"), // 替换为你要指定的本机IP地址
	}
	if common.Iface != "" {
		use_ip := net.ParseIP(common.Iface)
		if use_ip == nil {
			return false
		}
		local_ip = &net.IPAddr{
			IP: use_ip, // 替换为你要指定的本机IP地址
		}
	}
	target_ip := net.ParseIP(host)
	if target_ip == nil {
		return false
	}
	conn, err := net.DialIP("ip4:icmp", local_ip, &net.IPAddr{IP: target_ip})
	if err != nil {
		fmt.Println("DialIP error, check iface:", err)
		return false
	}

	defer conn.Close()
	if err := conn.SetDeadline(startTime.Add(time.Duration(common.PingTimeout) * time.Second)); err != nil {
		return false
	}
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

func RunPing(hostslist []string, chanHosts chan string) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func ExecCommandPing(ip string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	default: //linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") && strings.Count(outinfo.String(), ip) > 2 {
			return true
		} else {
			return false
		}
	}
}

func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}

func ArrayCountValueTop(arrInit []string, length int) {
	if len(arrInit) == 0 {
		return
	}
	//分别构建ip的b段和c段哈希表，键是 ipv4前两段或者前三段，分别表示B段和C段
	hash_ipb_map := make(map[string]int)
	hash_ipc_map := make(map[string]int)
	for _, value := range arrInit {
		ip_slice := strings.Split(value, ".")
		if len(ip_slice) == 4 {
			ip_b_key := fmt.Sprintf("%s.%s", ip_slice[0], ip_slice[1])
			ip_c_key := fmt.Sprintf("%s.%s.%s", ip_slice[0], ip_slice[1], ip_slice[2])

			if _, ok := hash_ipb_map[ip_b_key]; ok {
				hash_ipb_map[ip_b_key] += 1
			} else {
				hash_ipb_map[ip_b_key] = 1
			}

			if _, ok := hash_ipc_map[ip_c_key]; ok {
				hash_ipc_map[ip_c_key] += 1
			} else {
				hash_ipc_map[ip_c_key] = 1
			}
		} else {
			continue
		}
	}

	for ip_b, count := range hash_ipb_map {
		output := fmt.Sprintf("[*] LiveTop %-16s count: %d", ip_b+".0.0/16", count)
		common.LogSuccess(output)
	}

	for ip_c, count := range hash_ipc_map {
		output := fmt.Sprintf("[*] LiveTop %-16s count: %d", ip_c+".0/24", count)
		common.LogSuccess(output)
	}

}
