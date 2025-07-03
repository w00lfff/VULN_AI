package modules

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type URLAnalysisResult struct {
	URL           string   `json:"URL"`
	IsReachable   bool     `json:"IsReachable"`
	StatusCode    int      `json:"StatusCode"`
	ContentLength int64    `json:"ContentLength"`
	Priority      string   `json:"Priority"`
	Findings      []string `json:"Findings"`
	Headers       string   `json:"Headers"`
}
type URLAnalysisRequest struct {
	URLs       []string `form:"urls[]"`
	AIProvider string   `form:"aiProvider"`
	APIKey     string   `form:"apiKey"`
}

func HandleURLAnalysis(c *gin.Context) {
	var req URLAnalysisRequest
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
		req.URLs = append(req.URLs, parseURLsFromText(buf.String())...)
	}

	if len(req.URLs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No URLs provided"})
		return
	}

	jobID := uuid.New().String()
	go performURLAnalysis(req, jobID)
	c.JSON(http.StatusOK, gin.H{"jobID": jobID})
}

func performURLAnalysis(req URLAnalysisRequest, jobID string) {
	total := len(req.URLs)
	var processed int
	var mu sync.Mutex
	var finalResults []URLAnalysisResult
	var wg sync.WaitGroup
	guard := make(chan struct{}, 10)

	for _, u := range req.URLs {
		wg.Add(1)
		guard <- struct{}{}
		go func(targetURL string) {
			defer wg.Done()
			defer func() { <-guard }()
			for GetJobState(jobID) == "paused" {
				time.Sleep(500 * time.Millisecond)
			}
			result := analyzeSingleURL(targetURL)
			mu.Lock()
			processed++
			finalResults = append(finalResults, result)
			progress := (processed * 100) / total
			BroadcastProgress(jobID, progress, fmt.Sprintf("Analyzing %d/%d: %s", processed, total, targetURL))
			mu.Unlock()
		}(u)
	}
	wg.Wait()

	sort.SliceStable(finalResults, func(i, j int) bool {
		if finalResults[i].IsReachable != finalResults[j].IsReachable {
			return finalResults[i].IsReachable
		}
		priorityOrder := map[string]int{"High": 0, "Medium": 1, "Low": 2}
		return priorityOrder[finalResults[i].Priority] < priorityOrder[finalResults[j].Priority]
	})
	BroadcastFinalResults(jobID, finalResults)
}

func analyzeSingleURL(targetURL string) URLAnalysisResult {
	result := URLAnalysisResult{URL: targetURL, Priority: "Low"}
	findingsSet := make(map[string]bool)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		result.IsReachable = false
		return result
	}
	defer resp.Body.Close()
	result.IsReachable = true
	result.StatusCode = resp.StatusCode
	result.ContentLength = resp.ContentLength

	var headers strings.Builder
	for name, values := range resp.Header {
		for _, value := range values {
			headers.WriteString(fmt.Sprintf("%s: %s\n", name, value))
		}
	}
	result.Headers = headers.String()

	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	if server := resp.Header.Get("Server"); server != "" {
		findingsSet[fmt.Sprintf("Header - Server: %s", server)] = true
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(bodyBytes))
	if err == nil {
		sensitiveKeywords := []string{"api", "admin", "login", "dashboard", "config", "token", "password", "jwt"}
		doc.Find("a[href], script[src]").Each(func(i int, s *goquery.Selection) {
			path, _ := s.Attr("href")
			if src, exists := s.Attr("src"); exists {
				path = src
			}
			if absURL, err := resp.Request.URL.Parse(path); err == nil {
				for _, keyword := range sensitiveKeywords {
					if strings.Contains(strings.ToLower(absURL.String()), keyword) {
						findingsSet[fmt.Sprintf("Sensitive Link: %s", absURL.String())] = true
					}
				}
			}
		})
		if doc.Find("form[action*='login']").Length() > 0 || doc.Find("input[type='password']").Length() > 0 {
			findingsSet["Functionality: Login form detected"] = true
		}
	}
	apiKeyRegex := regexp.MustCompile(`(?i)['"](api_key|secret_key|token)['"]\s*[:=]\s*['"]([a-zA-Z0-9\-_]{20,})['"]`)
	if apiKeyRegex.Match(bodyBytes) {
		findingsSet["HIGH: Potential API key found in response body"] = true
	}
	for finding := range findingsSet {
		result.Findings = append(result.Findings, finding)
	}
	sort.Strings(result.Findings)
	if containsFinding(result.Findings, "HIGH:") {
		result.Priority = "High"
	} else if containsFinding(result.Findings, "Sensitive Link") || containsFinding(result.Findings, "Login form") {
		result.Priority = "Medium"
	}
	return result
}
func containsFinding(findings []string, substr string) bool {
	for _, f := range findings {
		if strings.Contains(f, substr) {
			return true
		}
	}
	return false
}
func parseURLsFromText(text string) []string {
	var urls []string
	for _, line := range strings.Split(text, "\n") {
		if u := strings.TrimSpace(line); u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}
