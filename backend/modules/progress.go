package modules

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

type ProgressUpdate struct {
	JobID    string      `json:"jobId"`
	Progress int         `json:"progress"`
	Message  string      `json:"message"`
	Results  interface{} `json:"results,omitempty"`
	IsFinal  bool        `json:"isFinal"`
}

// In-memory storage for final subdomain results
var (
	subdomainResults   = make(map[string][]AnalysisResult) // jobID -> results
	subdomainResultsMu sync.Mutex
)

var (
	clients = make(map[string][]*websocket.Conn)
	mu      sync.Mutex

	// Job state management
	jobStates   = make(map[string]string) // jobID -> "running" or "paused"
	jobStatesMu sync.Mutex
)

func RegisterClient(jobID string, conn *websocket.Conn) {
	mu.Lock()
	defer mu.Unlock()
	clients[jobID] = append(clients[jobID], conn)
}

func UnregisterClient(jobID string, conn *websocket.Conn) {
	mu.Lock()
	defer mu.Unlock()
	if conns, ok := clients[jobID]; ok {
		for i, c := range conns {
			if c == conn {
				// Corrected slice removal logic
				clients[jobID] = append(conns[:i], conns[i+1:]...)
				break
			}
		}
		if len(clients[jobID]) == 0 {
			delete(clients, jobID)
		}
	}
}

func BroadcastProgress(jobID string, progress int, message string) {
	broadcast(jobID, ProgressUpdate{
		JobID:    jobID,
		Progress: progress,
		Message:  message,
		IsFinal:  false,
	})
}

func BroadcastFinalResults(jobID string, results interface{}) {
	broadcast(jobID, ProgressUpdate{
		JobID:    jobID,
		Progress: 100,
		Message:  "Analysis complete. Results attached.",
		Results:  results,
		IsFinal:  true,
	})
}

func broadcast(jobID string, update ProgressUpdate) {
	mu.Lock()
	defer mu.Unlock()
	messageBytes, err := json.Marshal(update)
	if err != nil {
		log.Printf("Error marshalling progress update: %v", err)
		return
	}

	if conns, ok := clients[jobID]; ok {
		for _, conn := range conns {
			if err := conn.WriteMessage(websocket.TextMessage, messageBytes); err != nil {
				log.Printf("Error writing to WebSocket: %v", err)
			}
		}
	}
}

func SetJobState(jobID, state string) {
	jobStatesMu.Lock()
	defer jobStatesMu.Unlock()
	jobStates[jobID] = state
}

func GetJobState(jobID string) string {
	jobStatesMu.Lock()
	defer jobStatesMu.Unlock()
	return jobStates[jobID]
}

func StoreSubdomainResults(jobID string, results []AnalysisResult) {
	subdomainResultsMu.Lock()
	defer subdomainResultsMu.Unlock()
	subdomainResults[jobID] = results
}

func GetSubdomainResults(jobID string) ([]AnalysisResult, bool) {
	subdomainResultsMu.Lock()
	defer subdomainResultsMu.Unlock()
	results, ok := subdomainResults[jobID]
	return results, ok
}
