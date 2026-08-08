package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

func main() {
	var outputFormat string
	var recursive bool
	var showHelp bool

	var rawText string

	flag.StringVar(&outputFormat, "o", "table", "Output format: table, json, csv")
	flag.StringVar(&outputFormat, "output", "table", "Output format: table, json, csv")
	flag.StringVar(&rawText, "s", "", "Pass certificate PEM text directly as a string")
	flag.StringVar(&rawText, "text", "", "Pass certificate PEM text directly as a string")
	flag.BoolVar(&recursive, "r", false, "Recursively scan directories")
	flag.BoolVar(&recursive, "recursive", false, "Recursively scan directories")
	flag.BoolVar(&showHelp, "h", false, "Show help")
	flag.BoolVar(&showHelp, "help", false, "Show help")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: certscanner [options] [file|dir ...]\n\n")
		fmt.Fprintf(os.Stderr, "Scans X.509 certificate files (single or multi-cert bundles) and displays line numbers, subjects, domains, and expiration dates.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -s, --text string     Pass certificate PEM text directly\n")
		fmt.Fprintf(os.Stderr, "  -o, --output string   Output format (table, json, csv) (default \"table\")\n")
		fmt.Fprintf(os.Stderr, "  -r, --recursive       Recursively scan directories\n")
		fmt.Fprintf(os.Stderr, "  -h, --help            Show help\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  certscanner cert.pem\n")
		fmt.Fprintf(os.Stderr, "  certscanner -s \"$(pbpaste)\"\n")
		fmt.Fprintf(os.Stderr, "  certscanner (paste text, press Ctrl+D)\n")
		fmt.Fprintf(os.Stderr, "  cat cert.pem | certscanner\n")
	}

	flag.Parse()

	if showHelp {
		flag.Usage()
		os.Exit(0)
	}

	args := flag.Args()
	var allCerts []CertInfo

	if rawText != "" {
		certs, err := ScanReader(strings.NewReader(rawText), "inline")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning raw text input: %v\n", err)
			os.Exit(1)
		}
		allCerts = append(allCerts, certs...)
	} else if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			fmt.Fprintln(os.Stderr, "Paste PEM certificate content below and press Ctrl+D when done:")
		}

		certs, err := ScanReader(os.Stdin, "stdin")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning stdin: %v\n", err)
			os.Exit(1)
		}
		allCerts = append(allCerts, certs...)
	} else {
		filesToScan := collectFiles(args, recursive)
		if len(filesToScan) == 0 {
			fmt.Fprintf(os.Stderr, "No valid certificate files found.\n")
			os.Exit(1)
		}

		for _, file := range filesToScan {
			certs, err := ScanFile(file)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to scan %s: %v\n", file, err)
				continue
			}
			allCerts = append(allCerts, certs...)
		}
	}

	if len(allCerts) == 0 {
		fmt.Fprintf(os.Stderr, "No X.509 certificates found.\n")
		os.Exit(0)
	}

	switch strings.ToLower(outputFormat) {
	case "json":
		renderJSON(os.Stdout, allCerts)
	case "csv":
		renderCSV(os.Stdout, allCerts)
	case "table":
		renderTable(os.Stdout, allCerts)
	default:
		fmt.Fprintf(os.Stderr, "Unknown output format: %s. Supported formats: table, json, csv\n", outputFormat)
		os.Exit(1)
	}
}

func collectFiles(paths []string, recursive bool) []string {
	var files []string
	visited := make(map[string]bool)

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: cannot access %s: %v\n", p, err)
			continue
		}

		if !info.IsDir() {
			if !visited[p] {
				visited[p] = true
				files = append(files, p)
			}
			continue
		}

		// Handle directory
		walkFn := func(path string, d os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if path != p && !recursive {
					return filepath.SkipDir
				}
				return nil
			}

			// Accept typical cert file extensions or any non-hidden file
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".pem" || ext == ".crt" || ext == ".cer" || ext == ".cert" || ext == ".ca-bundle" || ext == ".key" || ext == ".txt" || ext == "" {
				if !visited[path] {
					visited[path] = true
					files = append(files, path)
				}
			}
			return nil
		}

		_ = filepath.Walk(p, walkFn)
	}

	return files
}

func renderTable(w io.Writer, certs []CertInfo) {
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)

	// Determine if multiple distinct file paths are present
	fileSet := make(map[string]bool)
	for _, c := range certs {
		fileSet[c.FilePath] = true
	}
	showFileCol := len(fileSet) > 1 || (len(fileSet) == 1 && certs[0].FilePath != "stdin")

	if showFileCol {
		fmt.Fprintln(tw, "FILE\tLINE\tSUBJECT\tDOMAIN(S)\tEXPIRE DATE\tSTATUS")
	} else {
		fmt.Fprintln(tw, "LINE\tSUBJECT\tDOMAIN(S)\tEXPIRE DATE\tSTATUS")
	}

	for _, c := range certs {
		domainsStr := strings.Join(c.Domains, ", ")
		if domainsStr == "" {
			domainsStr = "-"
		}

		expireStr := c.NotAfter.Format("2006-01-02 15:04:05 MST")
		statusStr := fmt.Sprintf("%d days left", c.DaysRemaining)
		if c.IsExpired {
			statusStr = fmt.Sprintf("EXPIRED (%d days ago)", -c.DaysRemaining)
		} else if c.DaysRemaining < 30 {
			statusStr = fmt.Sprintf("EXPIRING SOON (%d days left)", c.DaysRemaining)
		}

		subjectStr := c.Subject
		if len(subjectStr) > 40 {
			subjectStr = subjectStr[:37] + "..."
		}

		if showFileCol {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", c.FilePath, c.LineNumber, subjectStr, domainsStr, expireStr, statusStr)
		} else {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", c.LineNumber, subjectStr, domainsStr, expireStr, statusStr)
		}
	}

	tw.Flush()
}

func renderJSON(w io.Writer, certs []CertInfo) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(certs)
}

func renderCSV(w io.Writer, certs []CertInfo) {
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"FilePath", "LineNumber", "Subject", "CommonName", "Domains", "NotAfter", "DaysRemaining", "IsExpired"})

	for _, c := range certs {
		domainsStr := strings.Join(c.Domains, ";")
		_ = writer.Write([]string{
			c.FilePath,
			strconv.Itoa(c.LineNumber),
			c.Subject,
			c.CommonName,
			domainsStr,
			c.NotAfter.Format(time.RFC3339),
			strconv.Itoa(c.DaysRemaining),
			strconv.FormatBool(c.IsExpired),
		})
	}
	writer.Flush()
}
