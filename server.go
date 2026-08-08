package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ScanSummary holds aggregated metrics for a scan request.
type ScanSummary struct {
	Total        int `json:"total"`
	Valid        int `json:"valid"`
	ExpiringSoon int `json:"expiring_soon"`
	Expired      int `json:"expired"`
}

// ScanResponse is the standard JSON payload returned by POST /api/scan.
type ScanResponse struct {
	Summary      ScanSummary `json:"summary"`
	Certificates []CertInfo  `json:"certificates"`
	ScannedAt    time.Time   `json:"scanned_at"`
}

// ScanJSONRequest defines the JSON input format for POST /api/scan.
type ScanJSONRequest struct {
	PEM string `json:"pem"`
}

const (
	// MaxRequestBodySize limits HTTP POST body payloads to 2 MB to prevent Denial of Service (DoS) attacks.
	MaxRequestBodySize = 2 * 1024 * 1024
)

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	// Guardrail 1: Enforce Max Request Body Size (2 MB)
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodySize)

	contentType := r.Header.Get("Content-Type")
	var certs []CertInfo
	var scanErr error

	if strings.HasPrefix(contentType, "multipart/form-data") {
		err := r.ParseMultipartForm(MaxRequestBodySize)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse form or payload exceeded 2MB limit: %v", err), http.StatusRequestEntityTooLarge)
			return
		}
		var filesFound bool
		for _, fileHeaders := range r.MultipartForm.File {
			for _, fh := range fileHeaders {
				filesFound = true
				f, err := fh.Open()
				if err != nil {
					continue
				}
				c, err := ScanReader(f, fh.Filename)
				_ = f.Close()
				if err == nil {
					certs = append(certs, c...)
				}
			}
		}
		if !filesFound {
			http.Error(w, "No files uploaded in multipart request", http.StatusBadRequest)
			return
		}
	} else if strings.HasPrefix(contentType, "application/json") {
		var reqBody ScanJSONRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, fmt.Sprintf("Invalid JSON body or payload exceeded limit: %v", err), http.StatusBadRequest)
			return
		}
		certs, scanErr = ScanReader(strings.NewReader(reqBody.PEM), "request_body")
	} else {
		// Read raw request body
		certs, scanErr = ScanReader(r.Body, "request_body")
	}

	if scanErr != nil {
		if strings.Contains(scanErr.Error(), "http: request body too large") {
			http.Error(w, "Request body exceeded maximum size limit of 2MB", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, fmt.Sprintf("Error parsing certificates: %v", scanErr), http.StatusInternalServerError)
		return
	}

	summary := ScanSummary{
		Total: len(certs),
	}
	for _, c := range certs {
		if c.IsExpired {
			summary.Expired++
		} else if c.DaysRemaining < 30 {
			summary.ExpiringSoon++
			summary.Valid++
		} else {
			summary.Valid++
		}
	}

	if certs == nil {
		certs = []CertInfo{}
	}

	resp := ScanResponse{
		Summary:      summary,
		Certificates: certs,
		ScannedAt:    time.Now().UTC(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, indexHTML)
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

// StartServer initializes and launches the HTTP web server.
func StartServer(port int) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/health", handleHealth)
	mux.HandleFunc("/api/scan", handleScan)
	mux.HandleFunc("/", handleUI)

	handler := securityHeadersMiddleware(mux)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Printf("🔒 CertScanner Web Service listening on http://localhost:%d\n", port)
	fmt.Printf("   - API Endpoint: POST http://localhost:%d/api/scan (Max Body: 2MB)\n", port)
	fmt.Printf("   - Health Check: GET http://localhost:%d/health\n", port)
	fmt.Printf("   - Web UI:       http://localhost:%d/\n", port)

	return srv.ListenAndServe()
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CertScanner Web Service</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --accent-primary: #38bdf8;
            --accent-hover: #0284c7;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --badge-green: #22c55e;
            --badge-amber: #f59e0b;
            --badge-red: #ef4444;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem 1rem;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
        }

        header {
            text-align: center;
            margin-bottom: 2rem;
        }

        header h1 {
            font-size: 2.2rem;
            font-weight: 700;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        header p {
            color: var(--text-muted);
            font-size: 1.05rem;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }

        textarea {
            width: 100%;
            height: 180px;
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            color: #38bdf8;
            font-family: 'Fira Code', monospace;
            font-size: 0.9rem;
            padding: 1rem;
            resize: vertical;
            margin-bottom: 1rem;
        }

        textarea:focus {
            outline: none;
            border-color: var(--accent-primary);
            box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
        }

        .btn-row {
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        button {
            background: var(--accent-primary);
            color: #0f172a;
            font-weight: 600;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.2s ease;
        }

        button:hover {
            background: var(--accent-hover);
            color: #fff;
        }

        .file-upload {
            position: relative;
            display: inline-block;
        }

        .file-upload input[type="file"] {
            display: none;
        }

        .file-label {
            background: #334155;
            color: var(--text-main);
            padding: 0.75rem 1.25rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 500;
            display: inline-block;
        }

        .file-label:hover {
            background: #475569;
        }

        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .metric-box {
            background: #090d16;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
            text-align: center;
        }

        .metric-box .number {
            font-size: 1.8rem;
            font-weight: 700;
        }

        .metric-box .label {
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }

        th, td {
            padding: 0.85rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background: #090d16;
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        td {
            font-size: 0.9rem;
        }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }

        .badge-green { background: rgba(34, 197, 94, 0.15); color: var(--badge-green); border: 1px solid var(--badge-green); }
        .badge-amber { background: rgba(245, 158, 11, 0.15); color: var(--badge-amber); border: 1px solid var(--badge-amber); }
        .badge-red { background: rgba(239, 68, 68, 0.15); color: var(--badge-red); border: 1px solid var(--badge-red); }
        .line-badge { background: #334155; color: #f8fafc; font-family: 'Fira Code', monospace; padding: 0.2rem 0.5rem; border-radius: 4px; }

        .domain-tag {
            display: inline-block;
            background: #0f172a;
            border: 1px solid var(--border-color);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.8rem;
            margin: 0.1rem;
            font-family: 'Fira Code', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CertScanner Web Service</h1>
            <p>Paste certificate PEM contents or upload a file to analyze subjects, domains, line numbers, and expiration dates.</p>
        </header>

        <div class="card">
            <textarea id="pemInput" placeholder="Paste your -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE----- content here..."></textarea>
            <div class="btn-row">
                <button onclick="scanCertificates()">Scan Certificates</button>
                <div class="file-upload">
                    <label for="fileInput" class="file-label">📁 Choose File</label>
                    <input type="file" id="fileInput" onchange="handleFileUpload(event)">
                </div>
                <span id="fileName" style="color: var(--text-muted); font-size: 0.9rem;"></span>
            </div>
        </div>

        <div id="resultsCard" class="card" style="display: none;">
            <div class="metrics">
                <div class="metric-box"><div class="number" id="mTotal">0</div><div class="label">Total Certs</div></div>
                <div class="metric-box"><div class="number" style="color: var(--badge-green);" id="mValid">0</div><div class="label">Valid</div></div>
                <div class="metric-box"><div class="number" style="color: var(--badge-amber);" id="mExpiring">0</div><div class="label">Expiring Soon</div></div>
                <div class="metric-box"><div class="number" style="color: var(--badge-red);" id="mExpired">0</div><div class="label">Expired</div></div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Line</th>
                        <th>Subject</th>
                        <th>Domain(s)</th>
                        <th>Expiration Date</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="certTableBody"></tbody>
            </table>
        </div>
    </div>

    <script>
        async function scanCertificates() {
            const pem = document.getElementById('pemInput').value;
            if (!pem.trim()) return alert('Please paste certificate PEM content or select a file first.');

            try {
                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: pem
                });
                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                renderResults(data);
            } catch (err) {
                alert('Scan error: ' + err.message);
            }
        }

        function handleFileUpload(evt) {
            const file = evt.target.files[0];
            if (!file) return;
            document.getElementById('fileName').innerText = file.name;
            const reader = new FileReader();
            reader.onload = (e) => {
                document.getElementById('pemInput').value = e.target.result;
                scanCertificates();
            };
            reader.readAsText(file);
        }

        function renderResults(data) {
            document.getElementById('resultsCard').style.display = 'block';
            document.getElementById('mTotal').innerText = data.summary.total;
            document.getElementById('mValid').innerText = data.summary.valid;
            document.getElementById('mExpiring').innerText = data.summary.expiring_soon;
            document.getElementById('mExpired').innerText = data.summary.expired;

            const tbody = document.getElementById('certTableBody');
            tbody.innerHTML = '';

            if (data.certificates.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No certificates found in content.</td></tr>';
                return;
            }

            data.certificates.forEach(c => {
                const tr = document.createElement('tr');
                
                const domainsHtml = c.domains.map(d => '<span class="domain-tag">' + escapeHtml(d) + '</span>').join('') || '-';
                
                let badgeClass = 'badge-green';
                let statusText = c.days_remaining + ' days left';
                if (c.is_expired) {
                    badgeClass = 'badge-red';
                    statusText = 'EXPIRED (' + Math.abs(c.days_remaining) + ' days ago)';
                } else if (c.days_remaining < 30) {
                    badgeClass = 'badge-amber';
                    statusText = 'EXPIRING SOON (' + c.days_remaining + ' days left)';
                }

                tr.innerHTML = '<td><span class="line-badge">Line ' + c.line_number + '</span></td>' +
                    '<td><strong>' + escapeHtml(c.subject) + '</strong></td>' +
                    '<td>' + domainsHtml + '</td>' +
                    '<td>' + new Date(c.not_after).toLocaleString() + '</td>' +
                    '<td><span class="badge ' + badgeClass + '">' + statusText + '</span></td>';
                tbody.appendChild(tr);
            });
        }

        function escapeHtml(str) {
            return str ? str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : '';
        }
    </script>
</body>
</html>
`
