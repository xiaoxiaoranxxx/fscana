package Plugins

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/xxx/wscan/WebScan"
	"github.com/xxx/wscan/WebScan/lib"
	"github.com/xxx/wscan/common"
	"golang.org/x/text/encoding/simplifiedchinese"
)

type stringer interface {
	String() string
}

func WebTitle(info *common.HostInfo) error {
	common.Title_scan_ch <- 1
	if common.Scantype == "webpoc" {
		WebScan.WebScan(info)
		<-common.Title_scan_ch
		return nil
	}
	err, CheckData := GOWebTitle(info)
	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)

	if !common.NoPoc && err == nil {
		WebScan.WebScan(info)
	} else {
		// errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		// common.LogError(errlog)
	}
	<-common.Title_scan_ch
	return err
}
func GOWebTitle(info *common.HostInfo) (err error, CheckData []WebScan.CheckDatas) {
	if info.Url == "" {
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol := GetProtocol(host, common.TcpTimeout)
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		if !strings.Contains(info.Url, "://") {
			host := strings.Split(info.Url, "/")[0]
			protocol := GetProtocol(host, common.TcpTimeout)
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}

	err, result, CheckData := geturl(info, 1, CheckData)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	//有跳转
	if strings.Contains(result, "://") {
		info.Url = result
		err, result, CheckData = geturl(info, 3, CheckData)
		if err != nil {
			return
		}
	}

	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = geturl(info, 1, CheckData)
		//有跳转
		if strings.Contains(result, "://") {
			info.Url = result
			err, _, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return
			}
		}
	}
	//是否访问图标
	//err, _, CheckData = geturl(info, 2, CheckData)
	if err != nil {
		return
	}
	return
}

func toRaw(value interface{}) string {
	t := reflect.TypeOf(value)
	v := reflect.ValueOf(value)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}
	var raw string
	for i := 0; i < t.NumField(); i++ {
		// 从0开始获取Student所包含的key
		key := t.Field(i)
		// 通过interface方法来获取key所对应的值
		value := v.Field(i).Interface()
		var cell string
		switch s := value.(type) {
		case string:
			cell = s
		case []string:
			cell = strings.Join(s, "; ")
		case int:
			cell = strconv.Itoa(s)
		case stringer:
			cell = s.String()
		}
		if cell == "" {
			continue
		}
		raw += fmt.Sprintf("%s: %s\r\n", key.Name, cell)
	}
	return raw
}

func GetCertRaw(TLS *tls.ConnectionState) string {
	if TLS == nil {
		return ""
	}
	if len(TLS.PeerCertificates) == 0 {
		return ""
	}
	var raw string
	cert := TLS.PeerCertificates[0]
	raw += fmt.Sprint(toRaw(cert))
	raw += "\r\n"
	raw += "SUBJECT:\r\n"
	raw += fmt.Sprint(toRaw(cert.Subject))
	raw += "\r\n"
	raw += "Issuer:\r\n"
	raw += fmt.Sprint(toRaw(cert.Issuer))
	return raw
}

func geturl(info *common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	//flag 1 first try
	//flag 2 /favicon.ico
	//flag 3 302
	//flag 4 400 -> https

	Url := info.Url
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return err, "", CheckData
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,en;q=0.8,zh;q=0.7,*")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	//if common.Pocinfo.Cookie != "" {
	//	req.Header.Set("Cookie", "rememberMe=1;"+common.Pocinfo.Cookie)
	//} else {
	//	req.Header.Set("Cookie", "rememberMe=1")
	//}
	req.Header.Set("Connection", "close")
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
	} else {
		client = lib.Client
	}

	resp, err := client.Do(req)
	if err != nil {
		return err, "https", CheckData
	}

	defer resp.Body.Close()
	var title string
	body, err := getRespBody(resp)
	if err != nil {
		return err, "https", CheckData
	}

	var certInfo string = ""
	if len(Url) >= 5 && Url[:5] == "https" {
		certInfo = GetCertRaw(resp.TLS)
		certStrTmp := ""
		domainStr := ",Domain="
		if certInfo != "" {
			if index := strings.Index(certInfo, "Subject"); index != -1 {
				tmp := certInfo[index+9:]
				certStrTmp = strings.Split(tmp, "\r\n")[0]
			}

			if index := strings.Index(certInfo, "DNSNames"); index != -1 {
				tmp := certInfo[index+11:]
				domainStr += strings.Split(tmp, "\r\n")[0]
			}

			if len(certStrTmp) > 0 {
				certInfo = fmt.Sprintf("%s%s", certStrTmp, domainStr)
			} else {
				certInfo = strings.Replace(certInfo, "\n", "_", -1)
			}

			/*
				cert_info content like this:

				SignatureAlgorithm: SHA256-RSA
				PublicKeyAlgorithm: RSA
				Version: 3
				SerialNumber: 4183520561172206966195670189914676379
				Issuer: CN=TrustAsia TLS RSA CA,OU=Domain Validated SSL,O=TrustAsia Technologies\, Inc.,C=CN
				Subject: CN=hbsd.top
				NotBefore: 2023-06-19 00:00:00 +0000 UTC
				NotAfter: 2024-06-18 23:59:59 +0000 UTC
				MaxPathLen: -1
				OCSPServer: http://statuse.digitalcertvalidation.com
				IssuingCertificateURL: http://cacerts.digitalcertvalidation.com/TrustAsiaTLSRSACA.crt
				DNSNames: hbsd.top; www.hbsd.top
			*/
		}
	}

	CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header), resp.StatusCode, title, certInfo, ""})
	var reurl string
	if flag != 2 {
		if !utf8.Valid(body) {
			body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
		}
		title = gettitle(body)
		CheckData[len(CheckData)-1].Title = title
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}
		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
		}
		result := fmt.Sprintf("[*] JUMP %-25v code:%-3v len:%-6v title:%v", resp.Request.URL, resp.StatusCode, length, title)
		if reurl != "" {
			result += fmt.Sprintf(" Jump To: %s", reurl)
		} else { //own test
			jump_addr := getJSRedirectURL(body)
			if jump_addr != "None" {
				if strings.Contains(jump_addr, "http") {
					reurl = jump_addr
				} else {
					// 解析 URL
					parsedURL, err := url.Parse(Url)
					if err != nil {
						fmt.Println("parse url err:", err)
						return nil, "", CheckData
					}
					// 提取协议、主机名和端口（如果有）
					baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
					reurl = baseURL + "/" + jump_addr
				}
				result += fmt.Sprintf(" Jump To: %s", reurl)
			}
		}
		if reurl != "" {
			last := len(CheckData) - 1
			if CheckData[last].FirstURL == "" {
				CheckData[last].FirstURL = info.Url
			}
			common.LogSuccess(result)
		}
	}
	if reurl != "" {
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return nil, "https", CheckData
	}
	return nil, "", CheckData
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	return body, nil
}

func gettitle(body []byte) (title string) {
	re := regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	find := re.FindSubmatch(body)
	if len(find) > 1 {
		title = string(find[1])
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		if len(title) > 100 {
			title = title[:100]
		}
		if title == "" {
			title = "\"\"" //空格
		}
	} else {
		title = "None" //没有title
	}
	return title
}

func stripFirstChar(path string) string {
	if strings.HasPrefix(path, "/") {
		return path[1:]
	}
	return path
}

func getJSRedirectURL(body []byte) (redirectURL string) {
	// 匹配 location.href = 'target.jsp'
	re := regexp.MustCompile(`(?i)location\.href\s*=\s*['"]([^'"]+)['"]`)
	find := re.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 window.navigate('target.jsp')
	re = regexp.MustCompile(`(?i)window\.navigate\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	find = re.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 window.location.replace('target.jsp')
	re = regexp.MustCompile(`(?i)window\.location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	find = re.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 self.location='target.aspx'
	re = regexp.MustCompile(`(?i)self\.location\s*=\s*['"]([^'"]+)['"]`)
	find = re.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 top.location='target.aspx'
	re = regexp.MustCompile(`(?i)top\.location\s*=\s*['"]([^'"]+)['"]`)
	find = re.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 没有找到任何Jump To
	redirectURL = "None"
	return
}

func GetProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"
	//如果端口是80或443,跳过Protocol判断
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	socksconn, err := common.WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	conn := tls.Client(socksconn, &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					common.LogError(err)
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
