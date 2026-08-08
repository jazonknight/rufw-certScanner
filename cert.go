package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// CertInfo represents extracted metadata for a single certificate.
type CertInfo struct {
	FilePath      string    `json:"file_path"`
	LineNumber    int       `json:"line_number"`
	Subject       string    `json:"subject"`
	CommonName    string    `json:"common_name"`
	Domains       []string  `json:"domains"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	IsExpired     bool      `json:"is_expired"`
}

// ScanFile opens and parses certificates from a file path.
func ScanFile(filePath string) ([]CertInfo, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	return ScanReader(file, filePath)
}

// ScanReader reads from an io.Reader line-by-line and extracts all X.509 certificates with line numbers.
func ScanReader(r io.Reader, filename string) ([]CertInfo, error) {
	var certs []CertInfo
	scanner := bufio.NewScanner(r)

	lineNumber := 0
	inCert := false
	startLine := 0
	var pemLines []string

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "-----BEGIN CERTIFICATE-----") {
			inCert = true
			startLine = lineNumber
			pemLines = []string{line}
			continue
		}

		if inCert {
			pemLines = append(pemLines, line)
			if strings.Contains(trimmed, "-----END CERTIFICATE-----") {
				inCert = false
				pemData := []byte(strings.Join(pemLines, "\n"))
				block, _ := pem.Decode(pemData)
				if block != nil && (block.Type == "CERTIFICATE" || strings.Contains(block.Type, "CERTIFICATE")) {
					cert, err := x509.ParseCertificate(block.Bytes)
					if err == nil {
						info := extractCertInfo(cert, filename, startLine)
						certs = append(certs, info)
					}
				}
				pemLines = nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return certs, fmt.Errorf("error reading stream for %s: %w", filename, err)
	}

	return certs, nil
}

func extractCertInfo(cert *x509.Certificate, filename string, lineNo int) CertInfo {
	domainMap := make(map[string]bool)
	var domains []string

	if cert.Subject.CommonName != "" {
		domainMap[cert.Subject.CommonName] = true
		domains = append(domains, cert.Subject.CommonName)
	}

	for _, dns := range cert.DNSNames {
		if !domainMap[dns] {
			domainMap[dns] = true
			domains = append(domains, dns)
		}
	}

	for _, ip := range cert.IPAddresses {
		ipStr := ip.String()
		if !domainMap[ipStr] {
			domainMap[ipStr] = true
			domains = append(domains, ipStr)
		}
	}

	now := time.Now()
	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)

	subject := cert.Subject.String()
	if subject == "" {
		subject = cert.Subject.CommonName
	}

	issuer := cert.Issuer.String()
	if issuer == "" {
		issuer = cert.Issuer.CommonName
	}

	return CertInfo{
		FilePath:      filename,
		LineNumber:    lineNo,
		Subject:       subject,
		CommonName:    cert.Subject.CommonName,
		Domains:       domains,
		Issuer:        issuer,
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysRemaining: daysRemaining,
		IsExpired:     now.After(cert.NotAfter),
	}
}
