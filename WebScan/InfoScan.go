package WebScan

import (
	"crypto/md5"
	"fmt"
	"golang.org/x/net/html"
	"net/url"
	"regexp"
	"strings"

	"github.com/xxx/wscan/WebScan/info"
	"github.com/xxx/wscan/common"
	"github.com/xxx/wscan/mylib/appfinger"
	"github.com/xxx/wscan/mylib/appfinger/httpfinger"
)

type C_FingerPrint struct {
	ProductName []string
	Hostname    string
	Domain      string
	MACAddr     string
}

type CheckDatas struct {
	Body     []byte
	Headers  string
	HttpCode int
	Title    string
	Cert     string
	FirstURL string
}

func getCopyRight(body []byte) (copyRight string) {
	//regexPattern := `(?i)(\s*)(?:&copy;|©)\s*(\d{4}\s*)?([^<\n]+)`
	//regexPattern := `(?i)([^<>\n"]+)(\S*)([^<>\n"]+)(?:&copy;|©)([^<>\n"]+)(\S*)([^<>\n"]+)` // 共3个捕获组，因为(?:&copy;|©)是非捕获组
	//regexPattern := `(?i)([^<\n"]+)\s*(?:&copy;|©)\s*([^<>\n"]+)` // 共3个捕获组，因为(?:&copy;|©)是非捕获组
	regexPattern := `(?i)(\s*)([^<\n]+)(?:&copy;|©)\s*([^<\n="]+)` // 共3个捕获组，因为(?:&copy;|©)是非捕获组
	unescapedContent := html.UnescapeString(string(body))          // html实体解码
	re := regexp.MustCompile(regexPattern)

	// 查找所有匹配项
	matches := re.FindAllStringSubmatch(unescapedContent, -1)
	if len(matches) > 0 {
		match := matches[len(matches)-1]
		//fmt.Println(match[0])
		//fmt.Println(match[1])
		//fmt.Println(match[2])
		//fmt.Println(len(match))
		if len(match) >= 3 { // 共4个元素，第0个是所有匹配内容，其余3个是捕获组
			match[3] = strings.TrimSpace(match[3])
			match[2] = strings.TrimSpace(match[2])
			if match[3] != "" && !strings.Contains(match[3], "<") && !strings.Contains(match[3], ">") && !strings.Contains(match[3], "=") {
				copyRight = match[3]
			} else if match[2] != "" && !strings.Contains(match[2], "<") && !strings.Contains(match[2], ">") && !strings.Contains(match[2], "=") {
				copyRight = match[2]
			} else {
				copyRight = match[0]
			}
		} else if len(match) > 0 {
			copyRight = match[0]
		}

	}
	copyRight = strings.TrimSpace(copyRight)
	copyRight = strings.ReplaceAll(copyRight, "\n", "")
	if len(copyRight) > 70 {
		copyRight = copyRight[:70]
	}
	return
}

func getEmailByBody(body []byte) string {
	//re := regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	re := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}`)
	//re := regexp.MustCompile(`(?!.*\.\.)([a-zA-Z0-9.?_-` + "`" + `]+)@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}`)
	find := re.FindAllSubmatch(body, -1)
	emailText := ""
	uniqueMap := make(map[string]bool)

	if len(find) >= 1 {
		for _, emailGroup := range find {
			uniqueMap[string(emailGroup[0])] = true
		}
	}
	if len(uniqueMap) >= 1 {
		slice := []string{}
		for mail, _ := range uniqueMap {
			if len(mail) < 50 {
				slice = append(slice, mail)
			}
		}
		emailText = strings.Join(slice, ",")
	}

	return emailText
}

func InfoCheck(Url string, CheckData *[]CheckDatas) []string {
	var matched bool
	var infoname []string

	for _, data := range *CheckData {
		banner := &httpfinger.Banner{
			Protocol: "http",
			Port:     "",
			Header:   data.Headers,
			Body:     string(data.Body),
			Response: data.Headers + "\r\n\r\n" + string(data.Body),
			Cert:     data.Cert,
			Title:    data.Title,
			Hash:     "",
			Icon:     "",
			ICP:      "",
		}
		//fmt.Println("[debug] infoscan , get cert:", data.Cert)
		res := appfinger.Search_for_fscan(banner)
		copyRight := getCopyRight(data.Body)
		emailInBody := getEmailByBody(data.Body)

		if res != nil {
			// 解析URL字符串
			parsedURL, err := url.Parse(Url)
			if err != nil {
				fmt.Println("Error parsing URL:", err)
				return []string{""}
			}

			// 提取协议、主机名和端口部分
			protocol := parsedURL.Scheme
			host := parsedURL.Hostname()
			port := parsedURL.Port()
			if port == "" {
				if protocol == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			url_strip_path := ""
			if host == "" {
				url_strip_path = Url

			} else {
				url_strip_path = fmt.Sprintf("%s://%s:%s", protocol, host, port)
			}

			// 去掉切片元素首尾的空白符，然后用逗号拼接起来
			var resultSlice []string
			for _, productName := range res.ProductName {
				str_trim := strings.TrimSpace(productName)
				resultSlice = append(resultSlice, fmt.Sprintf("[%s]", str_trim))
			}
			if len(resultSlice) >= 1 {
				result := strings.Join(resultSlice, ", ")
				if copyRight == "" {
					result = fmt.Sprintf("[+] Product %-25v\t%d\t(%s)\t%s", url_strip_path, data.HttpCode, data.Title, result)
				} else {
					result = fmt.Sprintf("[+] Product %-25v\t%d\t(%s)\t%s, [copyright:%s]", url_strip_path, data.HttpCode, data.Title, result, copyRight)
				}
				if emailInBody != "" {
					result += fmt.Sprintf(", [email:%s]", emailInBody)
				}
				if data.Cert != "" {
					result += fmt.Sprintf(", [Cert:%s]", data.Cert)
				}
				if data.FirstURL != "" {
					result += fmt.Sprintf(", [From:%s]", data.FirstURL)
				}
				common.LogSuccess(result)

			} else { // 没有识别出产品
				if data.Title == "" {
					data.Title = "None"
				}
				if copyRight == "" {
					result := fmt.Sprintf("[+] Product %-25v\t%d\t(%s)", url_strip_path, data.HttpCode, data.Title)
					if emailInBody != "" {
						result += fmt.Sprintf("\t[email:%s]", emailInBody)
					}
					if data.Cert != "" {
						result += fmt.Sprintf("\t[Cert:%s]", data.Cert)
					}
					if data.FirstURL != "" {
						result += fmt.Sprintf("\t[From:%s]", data.FirstURL)
					}
					common.LogSuccess(result)
				} else {
					result := fmt.Sprintf("[+] Product %-25v\t%d\t(%s), [copyright:%s]", url_strip_path, data.HttpCode, data.Title, copyRight)
					if emailInBody != "" {
						result += fmt.Sprintf(", [email:%s]", emailInBody)
					}
					if data.Cert != "" {
						result += fmt.Sprintf(", [Cert:%s]", data.Cert)
					}
					if data.FirstURL != "" {
						result += fmt.Sprintf("\t[From:%s]", data.FirstURL)
					}
					common.LogSuccess(result)
				}

			}

		}

		for _, rule := range info.RuleDatas {
			if rule.Type == "code" {
				matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
			} else {
				matched, _ = regexp.MatchString(rule.Rule, data.Headers)
			}
			if matched == true {
				infoname = append(infoname, rule.Name)
			}
		}
		//flag, name := CalcMd5(data.Body)

		//if flag == true {
		//	infoname = append(infoname, name)
		//}
	}

	infoname = removeDuplicateElement(infoname)

	if len(infoname) > 0 {
		result := fmt.Sprintf("[+] InfoScan %-25v %s ", Url, infoname)
		common.LogSuccess(result)
		return infoname
	}
	return []string{""}
}

func CalcMd5(Body []byte) (bool, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range info.Md5Datas {
		if md5str == md5data.Md5Str {
			return true, md5data.Name
		}
	}
	return false, ""
}

func removeDuplicateElement(languages []string) []string {
	result := make([]string, 0, len(languages))
	temp := map[string]struct{}{}
	for _, item := range languages {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
