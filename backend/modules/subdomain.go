package modules

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type Tag struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
}
type AnalysisResult struct {
	Subdomain     string   `json:"Subdomain"`
	IsReachable   bool     `json:"IsReachable"`
	StatusCode    int      `json:"StatusCode"`
	ContentLength int64    `json:"ContentLength"`
	Priority      string   `json:"Priority"`
	Tags          []Tag    `json:"Tags"`
	Endpoints     []string `json:"Endpoints"`
	Headers       string   `json:"Headers"`
	Technologies  []string `json:"Technologies"`
	Report        string   `json:"Report"`
	RequestInfo   string   `json:"-"` // Don't send to frontend JSON, only for report
	FullResponse  string   `json:"-"`
}
type SubdomainAnalysisRequest struct {
	Subdomains        []string `form:"subdomains[]"`
	IsDeepCrawl       string   `form:"isDeepCrawl"`
	IsPortScan        string   `form:"isPortScan"`
	AIProvider        string   `form:"aiProvider"`
	APIKey            string   `form:"apiKey"`
	RequestsPerSecond string   `form:"requestsPerSecond"`
}

var topPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443}

func HandleSubdomainAnalysis(c *gin.Context) {
	var req SubdomainAnalysisRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid form data"})
		return
	}

	file, err := c.FormFile("file")
	if err == nil {
		fileHandle, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not open file"})
			return
		}
		defer fileHandle.Close()
		buf := new(bytes.Buffer)
		_, err = io.Copy(buf, fileHandle)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read file"})
			return
		}
		req.Subdomains = append(req.Subdomains, parseSubdomainsFromText(buf.String())...)
	}

	if len(req.Subdomains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No subdomains provided"})
		return
	}

	jobID := uuid.New().String()
	go performSubdomainAnalysis(req, jobID)
	c.JSON(http.StatusOK, gin.H{"jobID": jobID})
}

func performSubdomainAnalysis(req SubdomainAnalysisRequest, jobID string) {
	total := len(req.Subdomains)
	var processed int
	var mu sync.Mutex
	var finalResults []AnalysisResult
	var wg sync.WaitGroup
	rps, err := strconv.Atoi(req.RequestsPerSecond)
	if err != nil || rps <= 0 {
		rps = 10 // Default value
	}
	guard := make(chan struct{}, rps)

	for _, subdomain := range req.Subdomains {
		wg.Add(1)
		guard <- struct{}{}
		go func(sd string) {
			defer wg.Done()
			defer func() { <-guard }()
			for GetJobState(jobID) == "paused" {
				time.Sleep(500 * time.Millisecond)
			}
			result := analyzeSingleSubdomain(sd, req.IsDeepCrawl == "true", req.IsPortScan == "true")
			mu.Lock()
			processed++
			finalResults = append(finalResults, result)
			progress := (processed * 100) / total
			BroadcastProgress(jobID, progress, fmt.Sprintf("Scanning %d/%d: %s", processed, total, sd))
			mu.Unlock()
		}(subdomain)
	}
	wg.Wait()

	sort.SliceStable(finalResults, func(i, j int) bool {
		if finalResults[i].IsReachable != finalResults[j].IsReachable {
			return finalResults[i].IsReachable
		}
		priorityOrder := map[string]int{"High": 0, "Medium": 1, "Low": 2}
		return priorityOrder[finalResults[i].Priority] < priorityOrder[finalResults[j].Priority]
	})
	StoreSubdomainResults(jobID, finalResults)
	BroadcastFinalResults(jobID, finalResults)
}

func analyzeSingleSubdomain(subdomain string, isDeepCrawl bool, isPortScan bool) AnalysisResult {
	result := AnalysisResult{Subdomain: subdomain, Priority: "Low"}
	client := &http.Client{Timeout: 10 * time.Second}
	var req *http.Request
	var resp *http.Response
	var err error
	httpsURL := "https://" + subdomain
	req, _ = http.NewRequest("GET", httpsURL, nil)
	resp, err = client.Do(req)
	if err != nil {
		httpURL := "http://" + subdomain
		req, _ = http.NewRequest("GET", httpURL, nil)
		resp, err = client.Do(req)
	}

	if req != nil {
		reqDump, _ := httputil.DumpRequestOut(req, false) // Don't dump body for GET
		result.RequestInfo = string(reqDump)
	}

	if err != nil {
		result.IsReachable = false
		result.Report = generateReport(result, isDeepCrawl, isPortScan)
		return result
	}
	defer resp.Body.Close()

	result.IsReachable = true
	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength

	highPriorityKeywords := []string{"admin", "login", "portal", "dashboard", "api", "payment", "vpn", "remote", "cpanel", "ssh"}
	mediumPriorityKeywords := []string{"dev", "staging", "test", "uat", "demo", "git", "jira", "ci", "cd"}
	if containsAny(subdomain, highPriorityKeywords) {
		result.Priority = "High"
	} else if containsAny(subdomain, mediumPriorityKeywords) {
		result.Priority = "Medium"
	}

	// If both deepcrawl and portscan are false, return minimal info
	if !isDeepCrawl && !isPortScan {
		result.Report = generateReport(result, isDeepCrawl, isPortScan)
		return result
	}

	// Read body for further analysis
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		// Handle error if body can't be read, but proceed
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore the body for other readers

	respDump, _ := httputil.DumpResponse(resp, true)
	result.FullResponse = string(respDump)

	// If deepcrawl is true, collect headers, body preview, tech, endpoints
	if isDeepCrawl {
		var headers strings.Builder
		for name, values := range resp.Header {
			for _, value := range values {
				headers.WriteString(fmt.Sprintf("%s: %s\n", name, value))
			}
		}
		result.Headers = headers.String()

		// Wappalyzer tech detection
		wappalyzerClient, err := wappalyzer.New()
		if err == nil {
			techs := wappalyzerClient.Fingerprint(resp.Header, bodyBytes)
			for tech := range techs {
				result.Technologies = append(result.Technologies, tech)
				result.Tags = append(result.Tags, Tag{Name: "Tech: " + tech, Type: "tech"})
			}
		}

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
		if err == nil {
			endpointSet := make(map[string]bool)
			doc.Find("a[href], script[src]").Each(func(i int, s *goquery.Selection) {
				var path string
				if href, exists := s.Attr("href"); exists {
					path = href
				} else if src, exists := s.Attr("src"); exists {
					path = src
				}
				if isInterestingEndpoint(path) {
					endpointSet[toAbsoluteURL(resp.Request.URL, path)] = true
				}
			})
			for ep := range endpointSet {
				result.Endpoints = append(result.Endpoints, ep)
			}
			sort.Strings(result.Endpoints)
		}
	}

	// If portscan is true, add port scan results
	if isPortScan {
		for _, port := range scanPorts(subdomain) {
			result.Tags = append(result.Tags, Tag{Name: fmt.Sprintf("Port: %d", port), Type: "port"})
		}
	}

	result.Report = generateReport(result, isDeepCrawl, isPortScan)
	return result
}

// generateReport creates a human-readable report for each subdomain
func generateReport(result AnalysisResult, isDeepCrawl, isPortScan bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Subdomain: %s\n", result.Subdomain)
	fmt.Fprintf(&b, "Reachable: %v\n", result.IsReachable)
	fmt.Fprintf(&b, "Priority: %s\n", result.Priority)

	if !result.IsReachable {
		return b.String()
	}

	fmt.Fprintf(&b, "Status: %d\n", result.StatusCode)
	fmt.Fprintf(&b, "Content-Length: %d\n", result.ContentLength)

	if isDeepCrawl {
		if len(result.Technologies) > 0 {
			b.WriteString("\nTechnologies Detected:\n")
			for _, tech := range result.Technologies {
				fmt.Fprintf(&b, "- %s\n", tech)
			}
		}
		if len(result.Endpoints) > 0 {
			b.WriteString("\nDiscovered Endpoints:\n")
			for _, ep := range result.Endpoints {
				fmt.Fprintf(&b, "- %s\n", ep)
			}
		}
		if result.Headers != "" {
			b.WriteString("\nHeaders:\n" + result.Headers)
		}
	}

	if isPortScan {
		ports := []string{}
		for _, tag := range result.Tags {
			if tag.Type == "port" {
				ports = append(ports, strings.TrimPrefix(tag.Name, "Port: "))
			}
		}
		if len(ports) > 0 {
			b.WriteString("\nOpen Ports:\n" + strings.Join(ports, ", ") + "\n")
		}
	}

	if isDeepCrawl && result.RequestInfo != "" {
		b.WriteString("\n--- Request ---\n" + result.RequestInfo)
		b.WriteString("\n--- Full Response ---\n" + result.FullResponse)
	}
	return b.String()
}

func scanPorts(subdomain string) []int {
	var openPorts []int
	var wg sync.WaitGroup
	portsChan := make(chan int, len(topPorts))
	for _, port := range topPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", subdomain, p), 1*time.Second); err == nil {
				conn.Close()
				portsChan <- p
			}
		}(port)
	}
	go func() {
		wg.Wait()
		close(portsChan)
	}()
	for port := range portsChan {
		openPorts = append(openPorts, port)
	}
	sort.Ints(openPorts)
	return openPorts
}

func parseSubdomainsFromText(text string) []string {
	var subdomains []string
	for _, line := range strings.Split(text, "\n") {
		if sd := strings.TrimSpace(line); sd != "" {
			subdomains = append(subdomains, sd)
		}
	}
	return subdomains
}
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
func isInterestingEndpoint(path string) bool {
	path = strings.ToLower(path)
	if strings.HasPrefix(path, "#") || strings.HasPrefix(path, "mailto:") {
		return false
	}
	return true
}
func toAbsoluteURL(base *url.URL, path string) string {
	rel, err := url.Parse(path)
	if err != nil {
		return path
	}
	return base.ResolveReference(rel).String()
}
