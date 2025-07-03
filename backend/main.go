package main

import (
	"archive/zip"
	"bytes"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
	"vuln-ai-backend/modules"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	api := router.Group("/api/v1")
	{
		api.POST("/subdomains/analyze", modules.HandleSubdomainAnalysis)
		api.POST("/urls/analyze", modules.HandleURLAnalysis)
		api.POST("/ai/passive-scan", modules.HandlePassiveAIScan)
		api.POST("/ai/active-scan", modules.HandleActiveAIScan)
		api.POST("/ai/custom-scan", modules.HandleCustomAIScan)
		api.GET("/ws/progress/:jobID", handleProgressUpdates)
		api.POST("/jobs/:jobID/pause", func(c *gin.Context) {
			jobID := c.Param("jobID")
			modules.SetJobState(jobID, "paused")
			c.JSON(http.StatusOK, gin.H{"status": "paused"})
		})
		api.POST("/jobs/:jobID/resume", func(c *gin.Context) {
			jobID := c.Param("jobID")
			modules.SetJobState(jobID, "running")
			c.JSON(http.StatusOK, gin.H{"status": "running"})
		})
		api.GET("/subdomains/export/:jobID", func(c *gin.Context) {
			jobID := c.Param("jobID")
			deepcrawl := c.Query("deepcrawl") == "true"
			results, ok := modules.GetSubdomainResults(jobID)
			if !ok {
				c.JSON(http.StatusNotFound, gin.H{"error": "Results not found for this jobID"})
				return
			}
			if !deepcrawl {
				var lines []string
				for _, r := range results {
					if r.IsReachable {
						lines = append(lines, r.Subdomain)
					}
				}
				c.Header("Content-Type", "text/plain")
				c.Header("Content-Disposition", "attachment; filename=reachable_subdomains.txt")
				c.String(http.StatusOK, "%s", string([]byte(strings.Join(lines, "\n"))))
				return
			}
			buf := new(bytes.Buffer)
			zipWriter := zip.NewWriter(buf)
			var lines []string
			for _, r := range results {
				if r.IsReachable {
					lines = append(lines, r.Subdomain)
				}
			}
			folderName := "subdomain_reports/"
			f, err := zipWriter.Create(folderName + "reachable_subdomains.txt")
			if err != nil {
				log.Printf("Failed to create reachable_subdomains.txt in zip: %v", err)
			}
			_, err = f.Write([]byte(strings.Join(lines, "\n")))
			if err != nil {
				log.Printf("Failed to write reachable_subdomains.txt: %v", err)
			}
			sanitize := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
			for _, r := range results {
				if r.IsReachable {
					fname := folderName + sanitize.ReplaceAllString(r.Subdomain, "_") + ".txt"
					header := &zip.FileHeader{
						Name:   fname,
						Method: zip.Deflate,
					}
					header.SetModTime(time.Now())
					header.Flags |= 0x800
					fw, err := zipWriter.CreateHeader(header)
					if err != nil {
						log.Printf("Failed to create file %s in zip: %v", fname, err)
						continue
					}
					utf8bom := unicode.BOMOverride(unicode.UTF8.NewEncoder())
					writer := transform.NewWriter(fw, utf8bom)
					_, err = writer.Write([]byte(r.Report))
					if err != nil {
						log.Printf("Failed to write report for %s: %v", r.Subdomain, err)
					}
					writer.Close()
				}
			}
			err = zipWriter.Close()
			if err != nil {
				log.Printf("Failed to close zipWriter: %v", err)
			}
			c.Header("Content-Type", "application/zip")
			c.Header("Content-Disposition", "attachment; filename=subdomain_reports.zip")
			c.Data(http.StatusOK, "application/zip", buf.Bytes())
		})
	}

	log.Println("VULN_AI Go Backend (Final) starting on http://localhost:8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func handleProgressUpdates(c *gin.Context) {
	jobID := c.Param("jobID")
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed for job %s: %v", jobID, err)
		return
	}
	defer conn.Close()

	log.Printf("WebSocket connected for job %s", jobID)
	modules.RegisterClient(jobID, conn)
	defer modules.UnregisterClient(jobID, conn)

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			log.Printf("WebSocket disconnected for job %s", jobID)
			break
		}
	}
}
