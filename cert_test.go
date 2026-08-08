package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestCertPEM(commonName string, dnsNames []string, validDays int) ([]byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Duration(validDays) * 24 * time.Hour)

	serialNumberNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumberNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

func TestScanReaderSingleCert(t *testing.T) {
	pemBytes, err := generateTestCertPEM("example.com", []string{"example.com", "sub.example.com"}, 30)
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	certs, err := ScanReader(strings.NewReader(string(pemBytes)), "test.pem")
	if err != nil {
		t.Fatalf("ScanReader returned error: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected 1 cert, got %d", len(certs))
	}

	cert := certs[0]
	if cert.LineNumber != 1 {
		t.Errorf("Expected LineNumber 1, got %d", cert.LineNumber)
	}
	if cert.CommonName != "example.com" {
		t.Errorf("Expected CommonName 'example.com', got '%s'", cert.CommonName)
	}
	if len(cert.Domains) != 2 {
		t.Errorf("Expected 2 domains, got %d (%v)", len(cert.Domains), cert.Domains)
	}
}

func TestScanReaderMultiCertWithLineNumbers(t *testing.T) {
	pem1, _ := generateTestCertPEM("site1.com", []string{"site1.com"}, 30)
	pem2, _ := generateTestCertPEM("site2.com", []string{"site2.com", "api.site2.com"}, 60)

	var sb strings.Builder
	// Add 5 lines of header text
	sb.WriteString("# Certificate Bundle\n")
	sb.WriteString("# Line 2\n")
	sb.WriteString("# Line 3\n")
	sb.WriteString("# Line 4\n")
	sb.WriteString("\n") // Line 5

	// Line 6 starts cert 1
	sb.Write(pem1)

	// Add 3 blank lines
	sb.WriteString("\n\n\n")

	// Next cert start line
	cert1LineCount := strings.Count(string(pem1), "\n")
	expectedCert2StartLine := 6 + cert1LineCount + 3

	sb.Write(pem2)

	certs, err := ScanReader(strings.NewReader(sb.String()), "bundle.crt")
	if err != nil {
		t.Fatalf("ScanReader returned error: %v", err)
	}

	if len(certs) != 2 {
		t.Fatalf("Expected 2 certs in bundle, got %d", len(certs))
	}

	if certs[0].LineNumber != 6 {
		t.Errorf("Cert 1 starting line mismatch: expected 6, got %d", certs[0].LineNumber)
	}
	if certs[0].CommonName != "site1.com" {
		t.Errorf("Cert 1 CommonName mismatch: expected 'site1.com', got '%s'", certs[0].CommonName)
	}

	if certs[1].LineNumber != expectedCert2StartLine {
		t.Errorf("Cert 2 starting line mismatch: expected %d, got %d", expectedCert2StartLine, certs[1].LineNumber)
	}
	if certs[1].CommonName != "site2.com" {
		t.Errorf("Cert 2 CommonName mismatch: expected 'site2.com', got '%s'", certs[1].CommonName)
	}
}
