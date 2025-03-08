package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSPlugin определяет интерфейс плагина для обработки запросов.
type DNSPlugin interface {
	// Если возвращается blocked==true, то дальнейшая обработка прекращается, и в ответ сразу возвращается указанный ip.
	HandleQuery(domain string, qtype uint16) (blocked bool, ip net.IP)
}

// ------------------ PiHole Query Plugin ------------------

// PiHoleQueryPlugin выполняет DNS-запрос к Pi-hole-серверу и, если ответа нет или ответ свидетельствует о блокировке, сообщает о блокировке.
type PiHoleQueryPlugin struct {
	piholeAddr string
}

func (p *PiHoleQueryPlugin) HandleQuery(domain string, qtype uint16) (bool, net.IP) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	client := new(dns.Client)
	client.Timeout = 2 * time.Second
	addr := p.piholeAddr
	if addr == "" {
		addr = "pihole:53"
	}
	r, _, err := client.Exchange(m, addr)
	if err != nil {
		log.Printf("PiHole query error for domain %s: %v", domain, err)
		// При ошибке считаем домен заблокированным.
		return true, nil
	}
	if r == nil || len(r.Answer) == 0 {
		log.Printf("PiHole returned no answer for domain %s, blocking", domain)
		return true, nil
	}
	// Если все записи указывают на блокирующий IP (0.0.0.0 или ::), считаем домен заблокированным.
	blocked := true
	for _, ans := range r.Answer {
		switch rec := ans.(type) {
		case *dns.A:
			if rec.A.String() != "0.0.0.0" {
				blocked = false
			}
		case *dns.AAAA:
			if rec.AAAA.String() != "::" {
				blocked = false
			}
		}
	}
	if blocked {
		log.Printf("PiHole indicates domain %s is blocked", domain)
		if qtype == dns.TypeAAAA {
			return true, net.ParseIP("::")
		}
		return true, net.ParseIP("0.0.0.0")
	}
	// Если Pi-hole возвращает нормальный ответ, то считаем домен разрешённым.
	return false, nil
}

// ------------------ Regex Proxy Plugin ------------------

// RegexProxyPlugin проверяет домены по списку регулярных выражений и, если найдено совпадение, принудительно возвращает IP прокси.
type RegexProxyPlugin struct {
	Regexes []*regexp.Regexp
}

func (r *RegexProxyPlugin) HandleQuery(domain string, qtype uint16) (bool, net.IP) {
	for _, re := range r.Regexes {
		if re.MatchString(domain) {
			log.Printf("Domain %s matches regex forcing proxy", domain)
			if qtype == dns.TypeAAAA {
				return true, net.ParseIP(proxyIPStrV6)
			}
			return true, net.ParseIP(proxyIPStr)
		}
	}
	return false, nil
}

// ------------------ Глобальные переменные и настройки ------------------

// allowedDirectCountries – массив стран (код страны), для которых НЕ требуется проксирование.
// Если код страны из ответа API содержится в этом массиве, то возвращаются реальные IP, иначе – IP прокси.
var allowedDirectCountries = []string{"RU", "BY", "CN"}

// Для IPv4: excludeIPs – список IP, для которых всегда возвращаются реальные IP (например, IP самого прокси).
var excludeIPs = []string{os.Getenv("PROXY_SERVER_ADDRESS")}

// Для IPv6: excludeIPsV6 – список исключений для AAAA-запросов.
var excludeIPsV6 = []string{os.Getenv("PROXY_SERVER_ADDRESS_IPV6")}

// proxyIPStr – IP-адрес прокси для IPv4, который возвращается, если страна не входит в allowedDirectCountries.
var proxyIPStr = os.Getenv("PROXY_SERVER_ADDRESS")

// proxyIPStrV6 – IP-адрес прокси для IPv6.
var proxyIPStrV6 = os.Getenv("PROXY_SERVER_ADDRESS_IPV6")

// plugins – список плагинов, обрабатывающих запросы последовательно.
// Сначала вызывается PiHoleQueryPlugin, затем RegexProxyPlugin.
var plugins = []DNSPlugin{
	&PiHoleQueryPlugin{piholeAddr: "pihole"},
	&RegexProxyPlugin{Regexes: []*regexp.Regexp{
		// Пример: все домены вида *.google.com.
		regexp.MustCompile(`(?i)^(.+\.)?google\.com\.$`),
	}},
}

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

// lookupIPUsingDNS выполняет DNS-запрос к upstream-серверу, указанному в UPSTREAM_DNS.
// Если переменная не задана, по умолчанию используется 1.1.1.1:53.
func lookupIPUsingDNS(domain string, qtype uint16) ([]net.IP, error) {
	upstream := os.Getenv("UPSTREAM_DNS")
	if upstream == "" {
		upstream = "1.1.1.1:53"
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	client := new(dns.Client)
	client.Timeout = 5 * time.Second
	r, _, err := client.Exchange(m, upstream)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, ans := range r.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ips = append(ips, a.A)
		case *dns.AAAA:
			ips = append(ips, a.AAAA)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("no A/AAAA records found")
	}
	return ips, nil
}

// Структуры для JSON-ответа DoH.
type DNSAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type DNSQuestionJSON struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type DNSJSONResponse struct {
	Status   int               `json:"Status"`
	TC       bool              `json:"TC"`
	RD       bool              `json:"RD"`
	RA       bool              `json:"RA"`
	AD       bool              `json:"AD"`
	CD       bool              `json:"CD"`
	Question []DNSQuestionJSON `json:"Question"`
	Answer   []DNSAnswer       `json:"Answer,omitempty"`
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

	// 1. Выполняем обработку плагинами.
	for _, plugin := range plugins {
		blocked, pluginIP := plugin.HandleQuery(domain, question.Qtype)
		if blocked {
			rr := createRR(domain, question.Qtype, 300, pluginIP)
			resp.Answer = []dns.RR{rr}
			return resp
		}
	}

	// 2. Разрешаем домен через наш DNS-клиент.
	ips, err := lookupIPUsingDNS(domain, question.Qtype)
	if err != nil || len(ips) == 0 {
		resp.Rcode = dns.RcodeNameError
		return resp
	}

	// 3. Фильтруем IP по типу (A или AAAA).
	var relevantIPs []net.IP
	switch question.Qtype {
	case dns.TypeA:
		for _, ip := range ips {
			if ip.To4() != nil {
				relevantIPs = append(relevantIPs, ip)
			}
		}
	case dns.TypeAAAA:
		for _, ip := range ips {
			if ip.To4() == nil {
				relevantIPs = append(relevantIPs, ip)
			}
		}
	default:
		for _, ip := range ips {
			if ip.To4() != nil {
				relevantIPs = append(relevantIPs, ip)
			}
		}
	}
	if len(relevantIPs) == 0 {
		resp.Rcode = dns.RcodeNameError
		return resp
	}

	// 4. Проверяем исключения: если первый релевантный IP находится в списке исключений, возвращаем его.
	firstIPStr := relevantIPs[0].String()
	if question.Qtype == dns.TypeA {
		for _, exc := range excludeIPs {
			if firstIPStr == exc {
				for _, ip := range relevantIPs {
					rr := createRR(domain, dns.TypeA, 300, ip)
					resp.Answer = append(resp.Answer, rr)
				}
				return resp
			}
		}
	} else if question.Qtype == dns.TypeAAAA {
		for _, exc := range excludeIPsV6 {
			if firstIPStr == exc {
				for _, ip := range relevantIPs {
					rr := createRR(domain, dns.TypeAAAA, 300, ip)
					resp.Answer = append(resp.Answer, rr)
				}
				return resp
			}
		}
	}

	// 5. Получаем код страны через GeoIP API для первого релевантного IP.
	countryCode := getCountryCodeFromAPI(firstIPStr)
	allowed := false
	for _, c := range allowedDirectCountries {
		if c == countryCode {
			allowed = true
			break
		}
	}

	// 6. Формируем ответ: если страна разрешена – возвращаем реальные IP, иначе – IP прокси.
	if allowed {
		for _, ip := range relevantIPs {
			rr := createRR(domain, question.Qtype, 300, ip)
			resp.Answer = append(resp.Answer, rr)
		}
	} else {
		if question.Qtype == dns.TypeA {
			proxyIP := net.ParseIP(proxyIPStr)
			rr := createRR(domain, dns.TypeA, 60, proxyIP)
			resp.Answer = []dns.RR{rr}
		} else if question.Qtype == dns.TypeAAAA {
			proxyIP := net.ParseIP(proxyIPStrV6)
			if proxyIP == nil {
				resp.Rcode = dns.RcodeNameError
			} else {
				rr := createRR(domain, dns.TypeAAAA, 60, proxyIP)
				resp.Answer = []dns.RR{rr}
			}
		} else {
			resp.Rcode = dns.RcodeNameError
		}
	}

	return resp
}

// createRR создаёт ресурсную запись (A или AAAA) по типу.
func createRR(domain string, qtype uint16, ttl uint32, ip net.IP) dns.RR {
	switch qtype {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip.To4(),
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: ip,
		}
	default:
		return &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip.To4(),
		}
	}
}

// dohHandler обрабатывает запросы DoH.
// Поддерживаются два формата: бинарный (если передан параметр "dns") и JSON (если указан параметр "name" или accept = application/dns-json).
func dohHandler(w http.ResponseWriter, r *http.Request) {
	// Если есть параметр "name" или заголовок accept содержит "application/dns-json" – обрабатываем как JSON запрос.
	if r.URL.Query().Get("name") != "" || strings.Contains(r.Header.Get("accept"), "application/dns-json") {
		handleDohJSON(w, r)
		return
	}

	// Иначе – бинарный режим.
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

// handleDohJSON обрабатывает DoH-запросы в формате JSON.
func handleDohJSON(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "Missing name parameter", http.StatusBadRequest)
		return
	}
	typeStr := r.URL.Query().Get("type")
	if typeStr == "" {
		typeStr = "A"
	}
	qtype, ok := dns.StringToType[strings.ToUpper(typeStr)]
	if !ok {
		http.Error(w, "Unsupported query type", http.StatusBadRequest)
		return
	}

	reqMsg := new(dns.Msg)
	reqMsg.SetQuestion(dns.Fqdn(name), qtype)
	reqMsg.RecursionDesired = true

	respMsg := processDNSQuery(reqMsg)

	jsonResp := DNSJSONResponse{
		Status: int(respMsg.Rcode),
		TC:     respMsg.Truncated,
		RD:     respMsg.RecursionDesired,
		RA:     respMsg.RecursionAvailable,
		AD:     respMsg.AuthenticatedData,
		CD:     respMsg.CheckingDisabled,
	}
	for _, q := range respMsg.Question {
		jsonResp.Question = append(jsonResp.Question, DNSQuestionJSON{
			Name: q.Name,
			Type: q.Qtype,
		})
	}
	for _, rr := range respMsg.Answer {
		var data string
		switch v := rr.(type) {
		case *dns.A:
			data = v.A.String()
		case *dns.AAAA:
			data = v.AAAA.String()
		default:
			data = rr.String()
		}
		jsonResp.Answer = append(jsonResp.Answer, DNSAnswer{
			Name: rr.Header().Name,
			Type: rr.Header().Rrtype,
			TTL:  rr.Header().Ttl,
			Data: data,
		})
	}

	w.Header().Set("Content-Type", "application/dns-json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(jsonResp); err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

// startDoHServer запускает HTTP-сервер для DoH на порту 443.
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
	// Deprecated метод BuildNameToCertificate не используется.
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

	// Блокируем main, чтобы сервис работал бесконечно.
	select {}
}
