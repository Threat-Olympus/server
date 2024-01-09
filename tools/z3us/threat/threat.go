package threat

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Xss returns a string indicating potential XSS threats.
func Xss(url string) string {
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=\"javascript:alert('XSS');\">",
		"'><script>alert('XSS');</script>",
		"\";alert('XSS');",
		"'><img src=x onerror=alert('XSS');>",
	}

	result := "XSS Check Results:\n"

	for _, payload := range payloads {
		testURL := fmt.Sprintf("%s/vulnerable-endpoint?param=%s", url, payload)

		response, err := http.Get(testURL)
		if err != nil {
			result += fmt.Sprintf("Error sending GET request: %v\n", err)
			continue
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			result += fmt.Sprintf("Error reading response body: %v\n", err)
			continue
		}

		if strings.Contains(string(body), "XSS") {
			result += fmt.Sprintf("Potential XSS threat detected with payload: %s\n", payload)
		} else {
			result += fmt.Sprintf("No XSS threat detected with payload: %s\n", payload)
		}
	}

	return result
}

// BrokenAccess returns a string indicating potential broken access control issues.
func CheckBrokenAccess(urlString string, pathsToTest []string) string {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return fmt.Sprintf("Error parsing input URL: %v", err)
	}

	if len(pathsToTest) == 0 {
		pathsToTest = []string{"/"} // Default to checking only the root path
	}

	result := "Broken Access Control Check Results:\n"

	for _, path := range pathsToTest {
		testURL := fmt.Sprintf("%s%s", parsedURL.String(), path)

		response, err := http.Get(testURL)
		if err != nil {
			result += fmt.Sprintf("Error sending GET request: %v\n", err)
			continue
		}
		defer response.Body.Close()

		if response.StatusCode == http.StatusOK {
			result += fmt.Sprintf("Access to %s is possible. Potential broken access control detected.\n", testURL)
		} else {
			result += fmt.Sprintf("Access to %s is not allowed. Access control seems intact.\n", testURL)
		}
	}

	return result
}

// InsecureDesign returns a string indicating potential insecure design issues.
func InsecureDesign(url string) string {
	result := "Insecure Design Check Results:\n"

	checkHTTPScheme(url, &result)
	checkSensitiveInformationInURLs(url, &result)
	checkDirectoryListing(url, &result)
	checkCrossOriginResourceSharing(url, &result)
	checkMissingSecurityHeaders(url, &result)

	return result
}

func checkHTTPScheme(url string, result *string) {
	if !isHTTPS(url) {
		*result += "The website is using HTTP instead of HTTPS. Insecure design detected.\n"
	}
}

func checkSensitiveInformationInURLs(url string, result *string) {
	sensitiveParams := []string{"password", "apikey", "token", "secret"}
	for _, param := range sensitiveParams {
		if strings.Contains(url, param) {
			*result += fmt.Sprintf("Sensitive information (%s) is exposed in the URL. Insecure design detected.\n", param)
		}
	}
}

func checkDirectoryListing(url string, result *string) {
	directoryURL := fmt.Sprintf("%s/some-directory/", url)
	response, err := http.Get(directoryURL)
	if err != nil {
		*result += fmt.Sprintf("Error sending GET request: %v\n", err)
		return
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		*result += fmt.Sprintf("Error reading response body: %v\n", err)
		return
	}

	if strings.Contains(string(body), "<title>Index of") {
		*result += "Directory listing is enabled. Insecure design detected.\n"
	}
}

func checkCrossOriginResourceSharing(url string, result *string) {
	corsTestURL := "https://malicious-attacker.com"
	req, err := http.NewRequest("GET", corsTestURL, nil)
	if err != nil {
		*result += fmt.Sprintf("Error creating CORS test request: %v\n", err)
		return
	}

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		*result += fmt.Sprintf("Error sending CORS test request: %v\n", err)
		return
	}
	defer response.Body.Close()

	if response.Header.Get("Access-Control-Allow-Origin") == "*" {
		*result += "Insecure CORS configuration detected.\n"
	}
}

func checkMissingSecurityHeaders(url string, result *string) {
	securityHeaders := []string{"Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"}
	for _, header := range securityHeaders {
		if !hasHeader(url, header) {
			*result += fmt.Sprintf("Missing security header (%s). Insecure design detected.\n", header)
		}
	}
}

func isHTTPS(url string) bool {
	return strings.HasPrefix(url, "https://")
}

func hasHeader(url, header string) bool {
	response, err := http.Get(url)
	if err != nil {
		return false
	}
	defer response.Body.Close()

	return response.Header.Get(header) != ""
}

// OutdatedComponents returns a string indicating potential outdated components.
func OutdatedComponents(url string) string {
	result := "Outdated Components Check Results:\n"

	checkTesseractVersion(url, &result)
	// Add more checks as needed

	return result
}

func checkTesseractVersion(url string, result *string) {
	response, err := http.Get(url)
	if err != nil {
		*result += fmt.Sprintf("Error sending GET request: %v\n", err)
		return
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		*result += fmt.Sprintf("Error reading response body: %v\n", err)
		return
	}

	versionRegex := regexp.MustCompile(`Tesseract Version: (\d+\.\d+\.\d+)`)
	matches := versionRegex.FindStringSubmatch(string(body))

	if len(matches) > 1 {
		tesseractVersion := matches[1]
		*result += fmt.Sprintf("Detected Tesseract version: %s\n", tesseractVersion)

		if isOutdatedTesseractVersion(tesseractVersion) {
			*result += "The Tesseract version is outdated. Vulnerable component detected.\n"
		} else {
			*result += "The Tesseract version is up-to-date.\n"
		}
	} else {
		*result += "Could not determine the Tesseract version from the response.\n"
	}
}

func isOutdatedTesseractVersion(version string) bool {
	return version < "4.1.0"
}

// SqlInject returns a string indicating potential SQL injection vulnerabilities.
func SqlInject(url string) string {
	payloads := []string{
		"' OR '1'='1' --",
		"' OR '1'='1'; --",
		"1; DROP TABLE users; --",
		"1'; DROP TABLE users; --",
		"1'; DROP TABLE users; SELECT * FROM data; --",
	}

	result := "SQL Injection Check Results:\n"

	for _, payload := range payloads {
		testURL := fmt.Sprintf("%s/vulnerable-endpoint?param=%s", url, payload)

		response, err := http.Get(testURL)
		if err != nil {
			result += fmt.Sprintf("Error sending GET request: %v\n", err)
			continue
		}
		defer response.Body.Close()

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			result += fmt.Sprintf("Error reading response body: %v\n", err)
			continue
		}

		if strings.Contains(string(body), "error") {
			result += fmt.Sprintf("Potential SQL injection vulnerability detected with payload: %s\n", payload)
		} else {
			result += fmt.Sprintf("No SQL injection vulnerability detected with payload: %s\n", payload)
		}
	}

	return result
}
