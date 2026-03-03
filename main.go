package main

import (
    "fmt"
    "log"
    "net/http"
    "github.com/gorilla/mux"
    "jwt-auth-service/config"
    "jwt-auth-service/handlers"
    "jwt-auth-service/middleware"
)

func main() {
    // Load configuration
    err := config.LoadConfig()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }

    // Initialize logger
    handlers.InitLogger()
    defer handlers.CloseLogger()

    // Create router
    r := mux.NewRouter()

    // Public endpoints
    r.HandleFunc("/api/login", handlers.LoginHandler).Methods("POST")
    r.HandleFunc("/health", handlers.HealthCheck).Methods("GET")

    // Protected API endpoints
    api := r.PathPrefix("/api").Subrouter()
    api.Use(middleware.AuthMiddleware)
    api.HandleFunc("/proxy/{path:.*}", handlers.ProxyHandler)

    // Admin endpoint for logs
    r.HandleFunc("/admin/logs", handlers.GetLogs).Methods("GET")

    // Start server
    serverAddr := fmt.Sprintf(":%s", config.AppConfig.ServerPort)
    fmt.Printf("Server starting on port %s\n", config.AppConfig.ServerPort)
    fmt.Printf("Target API: %s\n", config.AppConfig.TargetAPI)
    fmt.Println("Available clients:")
    for _, client := range config.AppConfig.Clients {
        fmt.Printf("  - %s (ID: %s)\n", client.Name, client.ID)
    }

    log.Fatal(http.ListenAndServe(serverAddr, r))
}
