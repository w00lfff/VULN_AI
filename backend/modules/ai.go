package modules

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"github.com/sashabaranov/go-openai"
	"google.golang.org/api/option"
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

type CustomScanRequest struct {
	Target       string `json:"target"`
	CustomPrompt string `json:"customPrompt"`
	Report       string `json:"report"`
	AIProvider   string `json:"aiProvider"`
	APIKey       string `json:"apiKey"`
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

func HandleCustomAIScan(c *gin.Context) {
	var req CustomScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.CustomPrompt == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Custom prompt cannot be empty"})
		return
	}

	prompt := fmt.Sprintf(
		"You are an expert penetration tester. Analyze the following security report for the target '%s' and then answer the user's specific question. Provide a concise, expert-level answer.\n\n"+
			"--- Full Security Report ---\n"+
			"%s\n\n"+
			"--- End of Report ---\n\n"+
			"--- User's Question ---\n"+
			"%s",
		req.Target,
		req.Report,
		req.CustomPrompt,
	)

	result := callAIProvider(req.AIProvider, req.APIKey, prompt)
	c.JSON(http.StatusOK, gin.H{"summary": result})
}

// --- Core AI Interaction (Simulation) ---

func callAIProvider(provider, apiKey, prompt string) string {
	if apiKey == "" {
		return "AI analysis disabled. Please provide an API key."
	}

	ctx := context.Background()

	switch provider {
	case "google":
		client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
		if err != nil {
			log.Printf("Error creating Google AI client: %v", err)
			return "Error: Could not create Google AI client."
		}
		defer client.Close()

		model := client.GenerativeModel("gemini-1.5-flash-latest")
		resp, err := model.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			log.Printf("Error calling Google AI: %v", err)
			return fmt.Sprintf("Error from Google AI: %v", err)
		}

		if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
			if part, ok := resp.Candidates[0].Content.Parts[0].(genai.Text); ok {
				return string(part)
			}
		}
		return "Error: Received an empty or invalid response from Google AI."

	case "openai":
		client := openai.NewClient(apiKey)
		resp, err := client.CreateChatCompletion(
			ctx,
			openai.ChatCompletionRequest{
				Model:    openai.GPT3Dot5Turbo,
				Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: prompt}},
			},
		)
		if err != nil {
			log.Printf("Error calling OpenAI: %v", err)
			return fmt.Sprintf("Error from OpenAI: %v", err)
		}
		if len(resp.Choices) > 0 {
			return resp.Choices[0].Message.Content
		}
		return "Error: Received an empty response from OpenAI."

	case "deepseek":
		config := openai.DefaultConfig(apiKey)
		config.BaseURL = "https://api.deepseek.com"
		client := openai.NewClientWithConfig(config)
		resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{Model: "deepseek-chat", Messages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: prompt}}})
		if err != nil {
			log.Printf("Error calling Deepseek: %v", err)
			return fmt.Sprintf("Error from Deepseek: %v", err)
		}
		if len(resp.Choices) > 0 {
			return resp.Choices[0].Message.Content
		}
		return "Error: Received an empty response from Deepseek."

	default:
		return fmt.Sprintf("Error: Unknown AI provider '%s'. Supported providers are 'google', 'openai', and 'deepseek'.", provider)
	}
}
