package z3us

import (
	"fmt"
	"github.com/z3us/threat"
	"net/http"
)

// Z3us function now returns a map[string]string containing the results
func Z3us(target string, url []string) string {
	var result string

	// Call functions from the threat package
	result += CheckSecurityHeaders(target)
	result += CheckSSL(target)
	result += threat.SqlInject(target)
	result += threat.OutdatedComponents(target)
	result += threat.InsecureDesign(target)
	result += threat.Xss(target)
	result += threat.CheckBrokenAccess(target, url)

	return result
}

func CheckSecurityHeaders(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Sprintf("Error showing in HTTP request: %v\n", err)
	}
	defer resp.Body.Close()

	// Check security headers
	insecureHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
	}

	result := "Security Headers:\n"
	for _, header := range insecureHeaders {
		if value := resp.Header.Get(header); value != "" {
			result += fmt.Sprintf("%s: %s\n", header, value)
		}
	}

	return result
}

// CheckSSL checks SSL/TLS handshake for a given host.
func CheckSSL(url string) string {
	// Use http.Get instead of tls.Dial to skip certificate verification
	_, err := http.Get(url)
	if err != nil {
		op := "Error connecting through TLS: %v\n"
		return op
	}
	return "SSL/TLS Handshake Successful.\n"
}
