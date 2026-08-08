package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", body["status"])
	}
}

func TestScanEndpointRawPEM(t *testing.T) {
	pemBytes, err := generateTestCertPEM("web.example.com", []string{"web.example.com", "api.example.com"}, 45)
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/scan", bytes.NewReader(pemBytes))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handleScan(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var scanResp ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&scanResp); err != nil {
		t.Fatalf("Failed to decode ScanResponse: %v", err)
	}

	if scanResp.Summary.Total != 1 {
		t.Errorf("Expected summary total 1, got %d", scanResp.Summary.Total)
	}
	if len(scanResp.Certificates) != 1 {
		t.Fatalf("Expected 1 certificate in response, got %d", len(scanResp.Certificates))
	}

	cert := scanResp.Certificates[0]
	if cert.CommonName != "web.example.com" {
		t.Errorf("Expected CommonName 'web.example.com', got '%s'", cert.CommonName)
	}
	if cert.LineNumber != 1 {
		t.Errorf("Expected LineNumber 1, got %d", cert.LineNumber)
	}
}

func TestScanEndpointJSONPayload(t *testing.T) {
	pemBytes, err := generateTestCertPEM("json.example.com", []string{"json.example.com"}, 60)
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	payload := ScanJSONRequest{
		PEM: string(pemBytes),
	}
	jsonBody, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/scan", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handleScan(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var scanResp ScanResponse
	_ = json.NewDecoder(resp.Body).Decode(&scanResp)

	if scanResp.Summary.Total != 1 {
		t.Errorf("Expected summary total 1, got %d", scanResp.Summary.Total)
	}
	if scanResp.Certificates[0].CommonName != "json.example.com" {
		t.Errorf("Expected CommonName 'json.example.com', got '%s'", scanResp.Certificates[0].CommonName)
	}
}

func TestScanEndpointMultipart(t *testing.T) {
	pemBytes, err := generateTestCertPEM("upload.example.com", []string{"upload.example.com"}, 10)
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "upload.crt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	_, _ = part.Write(pemBytes)
	_ = writer.Close()

	req := httptest.NewRequest("POST", "/api/scan", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w := httptest.NewRecorder()

	handleScan(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}

	var scanResp ScanResponse
	_ = json.NewDecoder(resp.Body).Decode(&scanResp)

	if scanResp.Summary.Total != 1 {
		t.Errorf("Expected 1 cert, got %d", scanResp.Summary.Total)
	}
	if scanResp.Summary.ExpiringSoon != 1 {
		t.Errorf("Expected 1 expiring soon cert, got %d", scanResp.Summary.ExpiringSoon)
	}
}

func TestUIEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handleUI(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 OK, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Expected text/html content type, got '%s'", resp.Header.Get("Content-Type"))
	}
}

func TestScanEndpointExceedsMaxBodySize(t *testing.T) {
	// Create a payload larger than 2MB
	largePayload := make([]byte, MaxRequestBodySize+1024)
	for i := range largePayload {
		largePayload[i] = 'A'
	}

	req := httptest.NewRequest("POST", "/api/scan", bytes.NewReader(largePayload))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	handleScan(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected status 413 Request Entity Too Large or 500, got %d", resp.StatusCode)
	}
}
