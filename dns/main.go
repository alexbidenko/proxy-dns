package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

// DNSPlugin определяет интерфейс плагина для обработки запросов.
type DNSPlugin interface {
	HandleQuery(domain string, qtype uint16) (blocked bool, ip net.IP)
}

// PiHolePlugin – пример плагина, блокирующего домены (аналог Pi-hole).
type PiHolePlugin struct {
	blockedDomains []string
}

// HandleQuery возвращает true, если домен должен быть заблокирован.
func (p *PiHolePlugin) HandleQuery(domain string, qtype uint16) (bool, net.IP) {
	// Простая проверка: если домен точно совпадает или заканчивается на заблокированное значение.
	for _, blocked := range p.blockedDomains {
		if domain == blocked || (len(domain) > len(blocked) && domain[len(domain)-len(blocked):] == blocked) {
			log.Printf("Domain %s blocked by PiHolePlugin", domain)
			return true, nil
		}
	}
	return false, nil
}

// Инициализация плагина с жестко заданным списком заблокированных доменов.
var piHolePlugin = &PiHolePlugin{
	blockedDomains: []string{"ads.example.com.", "tracker.example.com."},
}

// Список подключённых плагинов.
var plugins = []DNSPlugin{piHolePlugin}

// allowedDirectCountries – массив стран (код страны), для которых не требуется проксирование.
// Если код страны из ответа API содержится в этом массиве, то возвращаются реальные IP, иначе – прокси.
var allowedDirectCountries = []string{"RU", "BY", "CN"}

// excludeIPs – список IP-адресов, для которых всегда возвращаются реальные IP (например, IP самого прокси).
var excludeIPs = []string{os.Getenv("PROXY_SERVER_ADDRESS")}

// proxyIPStr – IP-адрес прокси, который возвращается, если страна не входит в allowedDirectCountries.
var proxyIPStr = os.Getenv("PROXY_SERVER_ADDRESS")

// getCountryCodeFromAPI делает HTTP GET запрос к API геолокации и возвращает код страны.
func getCountryCodeFromAPI(ip string) string {
	url := fmt.Sprintf("%s/api/location/%s", os.Getenv("LOCATION_SERVER_ORIGIN"), ip)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Error calling GeoIP API for IP %s: %v", ip, err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("GeoIP API returned status %d for IP %s", resp.StatusCode, ip)
		return ""
	}
	var data struct {
		IP      string `json:"ip"`
		Code    string `json:"code"`
		Country string `json:"country"`
		Region  string `json:"region"`
		City    string `json:"city"`
	}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		log.Printf("Error decoding GeoIP response for IP %s: %v", ip, err)
		return ""
	}
	return data.Code
}

// processDNSQuery обрабатывает DNS-запрос и формирует ответ.
func processDNSQuery(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	if len(req.Question) == 0 {
		return resp
	}
	question := req.Question[0]
	domain := question.Name

	// 1. Проверка через плагины (например, Pi-hole).
	for _, plugin := range plugins {
		blocked, pluginIP := plugin.HandleQuery(domain, question.Qtype)
		if blocked {
			blockIP := pluginIP
			if blockIP == nil {
				blockIP = net.ParseIP("0.0.0.0")
			}
			a := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   blockIP,
			}
			resp.Answer = []dns.RR{a}
			return resp
		}
	}

	// 2. Разрешение домена через системный резолвер.
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		resp.Rcode = dns.RcodeNameError
		return resp
	}

	// 3. Если первый IP находится в списке исключений, возвращаем его напрямую.
	firstIPStr := ips[0].String()
	for _, exc := range excludeIPs {
		if firstIPStr == exc {
			for _, ip := range ips {
				if ip.To4() != nil {
					a := &dns.A{
						Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   ip,
					}
					resp.Answer = append(resp.Answer, a)
				}
			}
			return resp
		}
	}

	// 4. Получаем код страны через GeoIP API.
	countryCode := getCountryCodeFromAPI(firstIPStr)
	allowed := false
	for _, c := range allowedDirectCountries {
		if c == countryCode {
			allowed = true
			break
		}
	}

	// 5. Если страна разрешена – возвращаем реальные IP, иначе – IP прокси.
	if allowed {
		for _, ip := range ips {
			if ip.To4() != nil {
				a := &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   ip,
				}
				resp.Answer = append(resp.Answer, a)
			}
		}
	} else {
		proxyIP := net.ParseIP(proxyIPStr)
		a := &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   proxyIP,
		}
		resp.Answer = []dns.RR{a}
	}
	return resp
}

// dohHandler обрабатывает запросы DoH.
func dohHandler(w http.ResponseWriter, r *http.Request) {
	var reqData []byte
	if r.Method == http.MethodGet {
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns query parameter", http.StatusBadRequest)
			return
		}
		var err error
		reqData, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Failed to decode dns parameter", http.StatusBadRequest)
			return
		}
	} else if r.Method == http.MethodPost {
		var err error
		reqData, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}

	var reqMsg dns.Msg
	if err := reqMsg.Unpack(reqData); err != nil {
		http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest)
		return
	}
	respMsg := processDNSQuery(&reqMsg)
	respData, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Write(respData)
}

// startDoHServer запускает HTTP-сервер для DoH.
func startDoHServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dohHandler)
	addr := ":443"
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Printf("Starting DNS over HTTPS (DoH) on %s/dns-query", addr)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("DoH server failed: %v", err)
		}
	}()
}

// startDoTServer запускает сервер DNS over TLS (DoT) на порту 853.
// Если сертификаты не найдены или возникла ошибка загрузки, сервер не запускается, но остальные сервисы работают.
func startDoTServer() {
	certFile := "/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/dns.ab.tw1.su/dns.ab.tw1.su.crt"
	keyFile := "/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/dns.ab.tw1.su/dns.ab.tw1.su.key"
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("DoT certificate %s not found, skipping DoT server", certFile)
		return
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("DoT key %s not found, skipping DoT server", keyFile)
		return
	}
	tlsConfig := &tls.Config{}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("Error loading DoT certificate: %v, skipping DoT", err)
		return
	}
	tlsConfig.Certificates = []tls.Certificate{cert}
	server := &dns.Server{
		Addr:      ":853",
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := processDNSQuery(r)
			_ = w.WriteMsg(m)
		}),
	}
	log.Println("Starting DNS over TLS (DoT) on port 853")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("DoT server failed: %v", err)
		}
	}()
}

// startStandardDNSServer запускает стандартные DNS-сервисы по UDP и TCP на порту 53.
func startStandardDNSServer() {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := processDNSQuery(r)
		_ = w.WriteMsg(m)
	})

	// UDP
	go func() {
		server := &dns.Server{
			Addr:    ":53",
			Net:     "udp",
			Handler: handler,
		}
		log.Println("Starting standard DNS server on UDP :53")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start UDP server: %v", err)
		}
	}()

	// TCP
	go func() {
		server := &dns.Server{
			Addr:    ":53",
			Net:     "tcp",
			Handler: handler,
		}
		log.Println("Starting standard DNS server on TCP :53")
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start TCP server: %v", err)
		}
	}()
}

func main() {
	log.Println("Starting DNS server")
	startStandardDNSServer()
	startDoTServer()
	startDoHServer()

	// Блокировка main, чтобы сервис работал бесконечно.
	select {}
}
