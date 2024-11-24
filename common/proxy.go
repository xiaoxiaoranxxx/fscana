package common

import (
	"errors"
	proxy2 "github.com/xxx/wscan/mylib/proxy"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	local_ip := "0.0.0.0"
	if Iface != "" {
		local_ip = Iface
	}
	net_ip := net.ParseIP(local_ip)
	if net_ip == nil {
		net_ip = net.ParseIP("0.0.0.0")
	}
	local_addr := &net.TCPAddr{
		IP: net_ip, // 替换为你想要使用的本地IP地址
	}
	d := &net.Dialer{Timeout: timeout, LocalAddr: local_addr}
	return WrapperTCP(network, address, d)
}

func GetProxyDialer() interface{} {
	if Socks5Proxy == "" {
		local_ip := "0.0.0.0"
		if Iface != "" {
			local_ip = Iface
		}
		net_ip := net.ParseIP(local_ip)
		if net_ip == nil {
			net_ip = net.ParseIP("0.0.0.0")
		}
		local_addr := &net.UDPAddr{
			IP: net_ip, // 替换为你想要使用的本地IP地址
		}
		dialer := net.Dialer{Timeout: time.Duration(TcpTimeout) * time.Second, LocalAddr: local_addr}
		return dialer
	} else {
		forward := &net.Dialer{Timeout: time.Duration(TcpTimeout) * time.Second}
		dialer, err := Socks5Dailer(forward)
		if err != nil {
			return nil
		}
		return dialer
	}

}

func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	//get conn
	var conn net.Conn
	if Socks5Proxy == "" {
		var err error

		if network == "udp" {
			saddr := strings.Split(address, ":")
			targetIP := saddr[0]
			targetPort, _ := strconv.Atoi(saddr[1])
			udpAddr := &net.UDPAddr{
				IP:   net.ParseIP(targetIP),
				Port: targetPort,
			}
			//fmt.Println("[debug] target and port udp: ", targetIP, targetPort)
			socket, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				return nil, err
			}
			socket.SetDeadline(time.Now().Add(time.Duration(TcpTimeout) * time.Second))
			return socket, nil
		}
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			// fmt.Println(err)
			return nil, err
		}

		//own add
		// timeout := forward.Timeout
		// if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		// 	fmt.Println("Error setting conn write deadline:", err)
		// }

		// if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		// 	fmt.Println("Error setting conn write deadline:", err)
		// }

		// // 发送数据到连接
		// httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", address)
		// _, err = conn.Write([]byte(httpRequest))
		// if err != nil {
		// 	fmt.Println("Error writing to connection:", err)
		// 	return nil, err
		// }

		// // 从连接中读取响应
		// buffer := make([]byte, 10)
		// _, err = conn.Read(buffer)
		// if err != nil {
		// 	fmt.Println("Error reading from connection:", err)
		// 	return nil, err
		// }
		//end

	}

	timeout := forward.Timeout
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	return conn, nil

}

func Socks5Dailer(forward *net.Dialer) (proxy2.Dialer, error) {
	u, err := url.Parse(Socks5Proxy)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("Only support socks5")
	}
	address := u.Host
	var auth proxy2.Auth
	var dailer proxy2.Dialer
	if u.User.String() != "" {
		auth = proxy2.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy2.SOCKS5("tcp", address, &auth, forward)
	} else {
		dailer, err = proxy2.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}
