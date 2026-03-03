package handlers

import (
    "encoding/json"
     // "fmt"   // временно закомментировали
    "io"
    "log"
    "net/http"
    "os"
    "time"
    "jwt-auth-service/config"
    "jwt-auth-service/middleware"
    "jwt-auth-service/models"
)

var logger *log.Logger
var logFile *os.File

func InitLogger() {
    var err error
    logFile, err = os.OpenFile("logs/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal("Failed to open log file:", err)
    }
    logger = log.New(logFile, "", log.LstdFlags)
}

func CloseLogger() {
    if logFile != nil {
        logFile.Close()
    }
}

// LoginHandler handles client authentication
func LoginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }

    var loginReq models.LoginRequest
    err := json.NewDecoder(r.Body).Decode(&loginReq)
    if err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Find client
    client := config.GetClientByID(loginReq.ClientID)
    if client == nil || client.SecretKey != loginReq.SecretKey {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // Generate token
    token, expiresAt, err := middleware.GenerateToken(client)
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        return
    }

    response := models.TokenResponse{
        Token:     token,
        ExpiresAt: expiresAt.Format(time.RFC3339),
        TokenType: "Bearer",
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)

    // Log login event
    logger.Printf("Client %s (%s) logged in, token expires at %s", 
        client.ID, client.Name, expiresAt.Format(time.RFC3339))
}

// ProxyHandler forwards requests to target API
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
    startTime := time.Now()
    clientID := r.Header.Get("X-Client-ID")
    
    // Create target URL
    targetURL := config.AppConfig.TargetAPI + r.URL.Path[len("/api/proxy"):]
    if r.URL.RawQuery != "" {
        targetURL += "?" + r.URL.RawQuery
    }

    // Create new request
    proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
    if err != nil {
        http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
        return
    }

    // Copy headers
    proxyReq.Header = r.Header.Clone()
    proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)

    // Send request
    client := &http.Client{}
    resp, err := client.Do(proxyReq)
    if err != nil {
        http.Error(w, "Failed to forward request: "+err.Error(), http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copy response
    w.WriteHeader(resp.StatusCode)
    body, _ := io.ReadAll(resp.Body)
    w.Write(body)

    // Log the request
    duration := time.Since(startTime)
    logEntry := models.LogEntry{
        Timestamp:    time.Now(),
        ClientID:     clientID,
        Method:       r.Method,
        Path:         r.URL.Path,
        StatusCode:   resp.StatusCode,
        ResponseTime: duration.String(),
    }
    
    logJSON, _ := json.Marshal(logEntry)
    logger.Println(string(logJSON))
}

// HealthCheck handler
func HealthCheck(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "status": "healthy",
        "time":   time.Now().String(),
    })
}

// GetLogs handler (admin only - simplified for demo)
func GetLogs(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("X-Admin-Token") != "admin-secret" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    http.ServeFile(w, r, "logs/app.log")
}
