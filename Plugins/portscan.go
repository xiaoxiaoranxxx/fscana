package Plugins

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/xxx/wscan/common"
	"github.com/xxx/wscan/mylib/gonmap"
)

type Addr struct {
	ip   string
	port int
}

func PortScan(hostslist []string, ports string, timeout int64) []*PortInfo {
	var AliveAddress []*PortInfo
	probePorts := common.ParsePort(ports)
	if len(probePorts) == 0 {
		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
		return AliveAddress
	}
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	workers := common.PortScanThreads
	//Addrs := make(chan Addr, len(hostslist)*len(probePorts))
	//results := make(chan string, len(hostslist)*len(probePorts))
	Addrs := make(chan Addr, common.PortScanThreads)
	results := make(chan *PortInfo, common.PortScanThreads)

	var wg sync.WaitGroup

	//接收结果
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("[ERROR] Goroutine recv scan output panic: ", r)
			}
		}()
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {

		go func() {
			_addr := ""
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("[-] scan %s error: %v\n", _addr, err)
				}
			}()
			for addr := range Addrs {
				_addr = addr.ip + ":" + strconv.Itoa(addr.port)
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	//fmt.Println("[debug] return aliveArray:", AliveAddress)
	return AliveAddress
}

func PortConnect(addr Addr, respondingHosts chan<- *PortInfo, adjustedTimeout int64, wg *sync.WaitGroup) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[-] PortConnect error: %v\n", err)
		}
	}()

	host, port := addr.ip, addr.port
	if common.UseNmap {
		nmap := gonmap.New()
		//fmt.Println(nmap)
		status, response := nmap.ScanTimeout(host, port, time.Second*time.Duration(common.TcpTimeout*4), time.Second*time.Duration(common.TcpTimeout))
		res := &PortInfo{
			ip:       host,
			port:     strconv.Itoa(port),
			Response: response,
		}
		switch status {
		case gonmap.Closed:
			//fmt.Println("port ", port, "close")
		case gonmap.Open:
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			//respondingHosts <- address + "_unknow_"
			respondingHosts <- res
		case gonmap.NotMatched:
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			respondingHosts <- res
		case gonmap.Matched:
			//fmt.Println("[debug] get cert info:", response.FingerPrint.Info)
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open %s", address, response.FingerPrint.Service)
			common.LogSuccess(result)
			wg.Add(1)
			respondingHosts <- res
		case gonmap.Unknown:
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			respondingHosts <- res
		}
	} else {
		conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
		if err == nil {
			defer conn.Close()
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			res := &PortInfo{
				ip:   host,
				port: strconv.Itoa(port),
			}
			respondingHosts <- res
		}
	}

}

func NoPortScan(hostslist []string, ports string) (AliveAddress []*PortInfo) {
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	for _, port := range probePorts {
		for _, host := range hostslist {
			//address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, &PortInfo{
				ip:   host,
				port: strconv.Itoa(port),
			})
		}
	}
	return
}
