package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// main запускает два слушателя – один на порту 80 (HTTP) и другой на порту 443 (TLS).
func main() {
	go startListener(":80")
	go startListener(":443")

	// Блокируем main, чтобы программа не завершалась.
	select {}
}

// startListener запускает TCP‑слушатель на заданном адресе и для каждого входящего соединения вызывает handleConnection.
func startListener(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Ошибка прослушивания %s: %v", addr, err)
	}
	log.Printf("Proxy-сервер запущен на %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Ошибка Accept на %s: %v", addr, err)
			continue
		}
		go handleConnection(conn)
	}
}

// handleConnection анализирует первые байты входящего соединения, определяет целевой хост и устанавливает двунаправленное копирование данных.
func handleConnection(client net.Conn) {
	defer client.Close()
	// Устанавливаем временной дедлайн для первых байтов.
	client.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(client)

	// Пытаемся прочитать первый байт
	firstByte, err := br.Peek(1)
	if err != nil {
		log.Printf("Ошибка чтения первого байта: %v", err)
		return
	}

	var targetHost string

	// Если первый байт равен 0x16 – скорее всего TLS handshake (протокол на порту 443)
	if firstByte[0] == 0x16 {
		targetHost, err = extractSNI(br)
		if err != nil {
			log.Printf("Не удалось извлечь SNI: %v", err)
			return
		}
		// По умолчанию для TLS назначаем порт 443.
		targetHost = net.JoinHostPort(targetHost, "443")
	} else {
		// Иначе пытаемся разобрать HTTP-запрос и извлечь заголовок Host.
		targetHost, err = extractHostFromHTTP(br)
		if err != nil {
			log.Printf("Не удалось извлечь Host из HTTP запроса: %v", err)
			return
		}
		// Если порт не указан, берем его из локального адреса входящего соединения.
		if !strings.Contains(targetHost, ":") {
			localPort := "80"
			localAddr := client.LocalAddr().String()
			_, port, err := net.SplitHostPort(localAddr)
			if err == nil {
				localPort = port
			}
			targetHost = net.JoinHostPort(targetHost, localPort)
		}
	}

	// Сбрасываем дедлайн для длительного копирования.
	client.SetDeadline(time.Time{})
	log.Printf("Проксирование: подключаемся к целевому хосту %s", targetHost)

	// Устанавливаем соединение с целевым сервером.
	target, err := net.DialTimeout("tcp", targetHost, 5*time.Second)
	if err != nil {
		log.Printf("Ошибка подключения к %s: %v", targetHost, err)
		return
	}
	defer target.Close()

	// Начинаем двунаправленное копирование данных.
	go func() {
		// Если в буфере уже накоплены данные (через Peek), отправляем их в target.
		_, err := io.Copy(target, br)
		if err != nil {
			log.Printf("Ошибка копирования от клиента к целевому серверу: %v", err)
		}
		target.Close()
	}()
	_, err = io.Copy(client, target)
	if err != nil {
		log.Printf("Ошибка копирования от целевого сервера к клиенту: %v", err)
	}
}

// extractSNI извлекает SNI (Server Name Indication) из TLS ClientHello, не удаляя данные из буфера.
func extractSNI(br *bufio.Reader) (string, error) {
	// Читаем 5 байт TLS-заголовка.
	header, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	if header[0] != 0x16 {
		return "", errors.New("не TLS handshake")
	}
	// Вычисляем длину TLS-записи.
	recordLength := int(header[3])<<8 | int(header[4])
	data, err := br.Peek(5 + recordLength)
	if err != nil {
		return "", err
	}
	hsData := data[5:]
	// Проверяем, что это ClientHello (тип 1)
	if hsData[0] != 0x01 {
		return "", errors.New("не ClientHello")
	}
	offset := 1 + 3  // тип и длина handshake
	offset += 2 + 32 // версия и random
	if offset >= len(hsData) {
		return "", errors.New("ClientHello слишком короткий")
	}
	// Session ID
	sessionIDLen := int(hsData[offset])
	offset++
	offset += sessionIDLen
	if offset+2 > len(hsData) {
		return "", errors.New("ошибка после sessionID")
	}
	// Cipher Suites
	cipherSuitesLen := int(hsData[offset])<<8 | int(hsData[offset+1])
	offset += 2 + cipherSuitesLen
	if offset >= len(hsData) {
		return "", errors.New("ошибка после cipher suites")
	}
	// Compression Methods
	compMethodsLen := int(hsData[offset])
	offset++
	offset += compMethodsLen
	if offset+2 > len(hsData) {
		return "", errors.New("ошибка после методов сжатия")
	}
	// Extensions
	extensionsLength := int(hsData[offset])<<8 | int(hsData[offset+1])
	offset += 2
	endExtensions := offset + extensionsLength
	if endExtensions > len(hsData) {
		return "", errors.New("некорректная длина расширений")
	}
	// Ищем расширение SNI (тип 0)
	for offset+4 <= endExtensions {
		extType := int(hsData[offset])<<8 | int(hsData[offset+1])
		extLen := int(hsData[offset+2])<<8 | int(hsData[offset+3])
		offset += 4
		if offset+extLen > endExtensions {
			return "", errors.New("ошибка обработки расширения")
		}
		if extType == 0 {
			if extLen < 2 {
				return "", errors.New("SNI расширение слишком короткое")
			}
			listLen := int(hsData[offset])<<8 | int(hsData[offset+1])
			offset += 2
			endList := offset + listLen
			for offset+3 <= endList {
				nameType := hsData[offset]
				nameLen := int(hsData[offset+1])<<8 | int(hsData[offset+2])
				offset += 3
				if offset+nameLen > endList {
					return "", errors.New("ошибка обработки имени SNI")
				}
				if nameType == 0 {
					return string(hsData[offset : offset+nameLen]), nil
				}
				offset += nameLen
			}
		} else {
			offset += extLen
		}
	}
	return "", errors.New("SNI не найден")
}

// extractHostFromHTTP извлекает заголовок Host из HTTP-запроса, используя Peek для неразрушительного чтения.
func extractHostFromHTTP(br *bufio.Reader) (string, error) {
	const maxPeek = 8192
	data, err := br.Peek(maxPeek)
	if err != nil && err != io.EOF {
		return "", err
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return "", err
	}
	// Если используется CONNECT, то RequestURI уже содержит "host:port".
	if req.Method == http.MethodConnect {
		return req.RequestURI, nil
	}
	if req.Host == "" {
		return "", errors.New("нет заголовка Host")
	}
	return req.Host, nil
}
