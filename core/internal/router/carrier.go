package router

import "strings"

var carrierSuffixes = []string{

	"10010.com", "10010.cn", "10010.com.cn", "wo.cn", "wo.com.cn", "17wo.cn", "17wo.com",
	"186.cn", "chinaunicom.cn", "chinaunicom.com", "chinaunicom.com.cn", "wostore.cn",
	"unicompayment.com", "10155.com", "woread.com.cn", "wocloud.cn",

	"10086.cn", "10086.com", "chinamobile.com", "139.com", "migu.cn", "cmpassport.com",

	"189.cn", "10000.com", "10000.cn", "chinatelecom.com.cn", "chinatelecom.cn", "ctyun.cn",
	"21cn.com", "telecomjs.com",
}

var carrierSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(carrierSuffixes))
	for _, s := range carrierSuffixes {
		m[s] = struct{}{}
	}
	return m
}()

func IsCarrierDomain(domain string) bool {
	d := CleanLowerDomain(domain)
	for {
		if _, ok := carrierSet[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
}
