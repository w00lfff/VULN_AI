package modules

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// --- Structs for On-Demand AI Scans ---
type PassiveScanRequest struct {
	Target     string   `json:"target"`
	StatusCode int      `json:"statusCode"`
	Headers    string   `json:"headers"`
	Tech       []string `json:"tech"`
	AIProvider string   `json:"aiProvider"`
	APIKey     string   `json:"apiKey"`
}

type ActiveScanRequest struct {
	Target     string   `json:"target"`
	Endpoints  []string `json:"endpoints"`
	AIProvider string   `json:"aiProvider"`
	APIKey     string   `json:"apiKey"`
}

// --- API Handlers for AI Scans ---

func HandlePassiveAIScan(c *gin.Context) {
	var req PassiveScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	prompt := fmt.Sprintf(
		"You are an expert penetration tester. Analyze the following initial reconnaissance data for the target '%s'. "+
			"Identify likely technologies, interesting headers, and potential attack surfaces based *only* on this initial response. "+
			"Provide a concise summary.\n\n"+
			"--- Data ---\n"+
			"Status Code: %d\n"+
			"Technologies: %s\n"+
			"Response Headers:\n%s",
		req.Target,
		req.StatusCode,
		strings.Join(req.Tech, ", "),
		req.Headers,
	)

	result := callAIProvider(req.AIProvider, req.APIKey, prompt)
	c.JSON(http.StatusOK, gin.H{"summary": result})
}

func HandleActiveAIScan(c *gin.Context) {
	var req ActiveScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	prompt := fmt.Sprintf(
		"You are an expert penetration tester. Your task is to analyze the provided web asset ('%s') and its discovered endpoints to create a prioritized testing plan. Think step-by-step like a hacker.\n\n"+
			"1. **Initial Hypothesis:** Based on the target name and its endpoints, what is the likely purpose of this application?\n"+
			"2. **Endpoint Analysis:** Review this list of discovered endpoints. Which 3-5 endpoints are the most interesting to attack? Why? (e.g., API routes, admin paths, file uploads).\n"+
			"   - Endpoints: %s\n"+
			"3. **Vulnerability Hypothesis:** For the most interesting endpoints you identified, what specific, high-impact vulnerabilities would you test for first? (e.g., for '/api/users/{id}', test for IDOR; for '/login', test for SQLi).\n"+
			"4. **Raise Questions:** What are two critical questions you would seek to answer next to confirm a vulnerability? (e.g., 'Does the /api/v1/user/{id} endpoint properly validate user session?' or 'What happens if I send a POST request with a different Content-Type to /api/upload?').\n"+
			"5. **Final Summary:** Provide a concise summary of the top 2 most likely attack vectors for this target.",
		req.Target,
		strings.Join(req.Endpoints, ", "),
	)

	result := callAIProvider(req.AIProvider, req.APIKey, prompt)
	c.JSON(http.StatusOK, gin.H{"summary": result})
}

// --- Core AI Interaction (Simulation) ---

func callAIProvider(provider, apiKey, prompt string) string {
	if apiKey == "" {
		return "AI analysis disabled. Please provide an API key."
	}
	log.Printf("Simulating AI call to '%s'", provider)

	if strings.Contains(prompt, "Active Scan") || strings.Contains(prompt, "Vulnerability Hypothesis") {
		return "AI Active Scan Result:\n\n1. **Hypothesis:** This appears to be a standard web application with a user management API.\n2. **Interesting Endpoints:** /api/users, /admin/login, /upload. These offer direct interaction with data and elevated privileges.\n3. **Vulnerabilities:** Test for IDOR on /api/users, SQL Injection on /admin/login, and unrestricted file upload (RCE) on /upload.\n4. **Questions:** Is the session cookie on /admin/login properly validated? Does the /upload endpoint sanitize filenames to prevent path traversal?\n5. **Summary:** Top attack vectors are likely Insecure Direct Object References (IDOR) on the API and Remote Code Execution (RCE) via the file upload."
	}
	// Default Passive Scan response
	return "AI Passive Scan Result: The target returns a 200 OK status. Headers reveal it's running Nginx. The presence of a '/api' endpoint suggests a potential attack surface for API-specific vulnerabilities like improper rate limiting or authentication bypass."
}
