// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	noDeadline   = time.Time{}
	aLongTimeAgo = time.Unix(1, 0)
)

func (d *Dialer) connect(ctx context.Context, c net.Conn, address string) (_ net.Addr, ctxErr error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		c.SetDeadline(deadline)
		defer c.SetDeadline(noDeadline)
	}
	if ctx != context.Background() {
		errCh := make(chan error, 1)
		done := make(chan struct{})
		defer func() {
			close(done)
			if ctxErr == nil {
				ctxErr = <-errCh
			}
		}()
		go func() {
			select {
			case <-ctx.Done():
				c.SetDeadline(aLongTimeAgo)
				errCh <- ctx.Err()
			case <-done:
				errCh <- nil
			}
		}()
	}

	b := make([]byte, 0, 6+len(host)) // the size here is just an estimate
	b = append(b, Version5)
	if len(d.AuthMethods) == 0 || d.Authenticate == nil {
		b = append(b, 1, byte(AuthMethodNotRequired))
	} else {
		ams := d.AuthMethods
		if len(ams) > 255 {
			return nil, errors.New("too many authentication methods")
		}
		b = append(b, byte(len(ams)))
		for _, am := range ams {
			b = append(b, byte(am))
		}
	}
	if _, ctxErr = c.Write(b); ctxErr != nil {
		return
	}

	if _, ctxErr = io.ReadFull(c, b[:2]); ctxErr != nil {
		return
	}
	if b[0] != Version5 {
		return nil, errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	am := AuthMethod(b[1])
	if am == AuthMethodNoAcceptableMethods {
		return nil, errors.New("no acceptable authentication methods")
	}
	if d.Authenticate != nil {
		if ctxErr = d.Authenticate(ctx, c, am); ctxErr != nil {
			return
		}
	}

	b = b[:0]
	b = append(b, Version5, byte(d.cmd), 0)
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, AddrTypeIPv4)
			b = append(b, ip4...)
		} else if ip6 := ip.To16(); ip6 != nil {
			b = append(b, AddrTypeIPv6)
			b = append(b, ip6...)
		} else {
			return nil, errors.New("unknown address type")
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("FQDN too long")
		}
		b = append(b, AddrTypeFQDN)
		b = append(b, byte(len(host)))
		b = append(b, host...)
	}
	b = append(b, byte(port>>8), byte(port))
	if _, ctxErr = c.Write(b); ctxErr != nil {
		return
	}

	if _, ctxErr = io.ReadFull(c, b[:4]); ctxErr != nil {
		return
	}
	if b[0] != Version5 {
		return nil, errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	if cmdErr := Reply(b[1]); cmdErr != StatusSucceeded {
		return nil, errors.New("unknown error " + cmdErr.String())
	}
	if b[2] != 0 {
		return nil, errors.New("non-zero reserved field")
	}
	l := 2
	var a Addr
	switch b[3] {
	case AddrTypeIPv4:
		l += net.IPv4len
		a.IP = make(net.IP, net.IPv4len)
	case AddrTypeIPv6:
		l += net.IPv6len
		a.IP = make(net.IP, net.IPv6len)
	case AddrTypeFQDN:
		if _, err := io.ReadFull(c, b[:1]); err != nil {
			return nil, err
		}
		l += int(b[0])
	default:
		return nil, errors.New("unknown address type " + strconv.Itoa(int(b[3])))
	}
	if cap(b) < l {
		b = make([]byte, l)
	} else {
		b = b[:l]
	}
	if _, ctxErr = io.ReadFull(c, b); ctxErr != nil {
		return
	}
	if a.IP != nil {
		copy(a.IP, b)
	} else {
		a.Name = string(b[:len(b)-2])
	}
	a.Port = int(b[len(b)-2])<<8 | int(b[len(b)-1])
	return &a, nil
}

type UDPConnSocks5 struct {
	*net.UDPConn
	SocksHeader *bytes.Buffer
}

// Write implements the Conn Write method.
func (c *UDPConnSocks5) Write(b []byte) (int, error) {
	//fmt.Println("[+] write func: header= ", c.SocksHeader.Bytes())
	body := append([]byte{}, c.SocksHeader.Bytes()...)
	body = append(body, b...)
	//fmt.Println("[+] write func: total data = ", body)

	res, err := c.UDPConn.Write(body)
	//fmt.Println("[+] write func: write ok = ", res, err)

	return res, err
}

// ReadFrom(p []byte) (n int, addr Addr, err error)
func (c *UDPConnSocks5) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	length := c.SocksHeader.Len()
	n, a, err := c.UDPConn.ReadFrom(b)
	//fmt.Println("[+] write func: read ok = ", n, err)
	if err != nil {
		return n, a, err
	} else {
		b = b[length:]
		n = n - length
	}
	return n, a, err
}

func (d *Dialer) connectUDP(ctx context.Context, c net.Conn, address string) (udpConn *UDPConnSocks5, ctxErr error) {

	//fmt.Println("[+] start udp conn...")
	host, port, err := splitHostPort(address)
	//fmt.Println("[+] get host port:", host, port)

	if err != nil {
		return udpConn, err
	}
	if deadline, ok := ctx.Deadline(); ok && !deadline.IsZero() {
		c.SetDeadline(deadline)
		defer c.SetDeadline(noDeadline)
	}
	if ctx != context.Background() {
		errCh := make(chan error, 1)
		done := make(chan struct{})
		defer func() {
			close(done)
			if ctxErr == nil {
				ctxErr = <-errCh
			}
		}()
		go func() {
			select {
			case <-ctx.Done():
				c.SetDeadline(aLongTimeAgo)
				errCh <- ctx.Err()
			case <-done:
				errCh <- nil
			}
		}()
	}

	b := make([]byte, 0, 6+len(host)) // the size here is just an estimate
	b = append(b, Version5)
	if len(d.AuthMethods) == 0 || d.Authenticate == nil {
		b = append(b, 1, byte(AuthMethodNotRequired))
	} else {
		ams := d.AuthMethods
		if len(ams) > 255 {
			return udpConn, errors.New("too many authentication methods")
		}
		b = append(b, byte(len(ams)))
		for _, am := range ams {
			b = append(b, byte(am))
		}
	}
	if _, ctxErr = c.Write(b); ctxErr != nil {
		return
	}

	if _, ctxErr = io.ReadFull(c, b[:2]); ctxErr != nil {
		return
	}
	if b[0] != Version5 {
		return udpConn, errors.New("unexpected protocol version " + strconv.Itoa(int(b[0])))
	}
	am := AuthMethod(b[1])
	if am == AuthMethodNoAcceptableMethods {
		return udpConn, errors.New("no acceptable authentication methods")
	}
	if d.Authenticate != nil {
		if ctxErr = d.Authenticate(ctx, c, am); ctxErr != nil {
			return
		}
	}

	b = b[:0]
	b = append(b, Version5, 0x3, 0)
	udpAssociateRequest := []byte{
		0x05, 0x03, 0x00, 0x01, // VER = 5, CMD = 3 (UDP Associate), RSV, ATYP = 1 (IPv4)
		0x00, 0x00, 0x00, 0x00, // IP = 0.0.0.0 (无特定目标)
		0x00, 0x00, // Port = 0
	}
	//if ip := net.ParseIP(host); ip != nil {
	//	if ip4 := ip.To4(); ip4 != nil {
	//		b = append(b, AddrTypeIPv4)
	//		b = append(b, ip4...)
	//	} else if ip6 := ip.To16(); ip6 != nil {
	//		b = append(b, AddrTypeIPv6)
	//		b = append(b, ip6...)
	//	} else {
	//		return nil, errors.New("unknown address type")
	//	}
	//} else {
	//	if len(host) > 255 {
	//		return nil, errors.New("FQDN too long")
	//	}
	//	b = append(b, AddrTypeFQDN)
	//	b = append(b, byte(len(host)))
	//	b = append(b, host...)
	//}
	//b = append(b, byte(port>>8), byte(port))
	if _, ctxErr = c.Write(udpAssociateRequest); ctxErr != nil {
		return
	}

	// 接收UDP Associate响应，获取SOCKS5代理指定的UDP端口
	response := make([]byte, 10)
	if _, ctxErr = io.ReadFull(c, response); ctxErr != nil {
		return
	}
	//fmt.Println("[+] reading 10 byte ok!")
	//fmt.Println("recv: ", response)

	// 获取代理服务器指定的UDP端口
	var udpPort uint16
	if response[3] == 0x1 {
		//fmt.Println("ipv4")
		udpPort = binary.BigEndian.Uint16(response[8:10])
	} else if response[3] == 0x4 {
		//fmt.Println("ipv6")
		tmpRev := make([]byte, 12)
		if _, ctxErr = io.ReadFull(c, tmpRev); ctxErr != nil {
			return
		}
		udpPort = binary.BigEndian.Uint16(response[10:12])
	} else {
		return
	}
	//fmt.Println("udp port:", udpPort)
	//fmt.Println("res:", response)

	// 构造SOCKS5 UDP封装数据包
	buf := new(bytes.Buffer)
	// UDP头：RSV, FRAG, ATYP
	buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	// DST.ADDR：目标IP地址
	dstIP := net.ParseIP(host).To4()
	buf.Write(dstIP)
	// DST.PORT：目标端口
	binary.Write(buf, binary.BigEndian, uint16(port))

	//fmt.Println("proxy server: ", strings.Split(c.RemoteAddr().String(), ":")[0], "proxy udp port:", udpPort)
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP(strings.Split(c.RemoteAddr().String(), ":")[0]), // 代理服务器的IP
		Port: int(udpPort),
	}

	// 3. 建立UDP连接，并发送目标数据包
	udpConnRaw, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Fatalf("can not conn to proxy server with udp: %v", err)
	}

	udpConn = &UDPConnSocks5{
		SocksHeader: buf,
		UDPConn:     udpConnRaw,
	}

	//message := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1}
	//udpConn.Write(message)
	//readBuf := make([]byte, 1024)
	//udpConn.SetReadDeadline(time.Now().Add(20 * time.Second))
	//n, _, err := udpConn.ReadFrom(readBuf)
	//fmt.Println("get n=", n)
	//if err != nil {
	//	log.Printf("未收到目标服务器响应或发生错误: %v", err)
	//} else {
	//	fmt.Printf("收到响应: %s\n", string(readBuf[:n]))
	//}
	return udpConn, nil
}

func splitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}
	portnum, err := strconv.Atoi(port)
	if err != nil {
		return "", 0, err
	}
	if 1 > portnum || portnum > 0xffff {
		return "", 0, errors.New("port number out of range " + port)
	}
	return host, portnum, nil
}
