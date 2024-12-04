package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"jwt-auth/config"
	"jwt-auth/internal/handlers"
	"jwt-auth/internal/models"
	"jwt-auth/internal/packages"
	"jwt-auth/internal/repositories"
	"jwt-auth/internal/services"
	"log"
)

func NewDBPool(connString string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	pool, err := NewDBPool(cfg.PostgresURL())
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	emailChan := make(chan models.EmailChan, 100)
	stopChan := make(chan bool)

	email := packages.NewEmail(cfg.SMTPFrom, cfg.SMTPUsername, cfg.SMTPPass, cfg.SMTPHost, cfg.SMTPPort, emailChan, stopChan)
	go email.EmailSender()

	authRepo := repositories.NewAuthRepository(pool)
	authService := services.NewAuthService(*cfg, *authRepo, packages.NewTokens(), emailChan)

	handler := handlers.NewHandler(authService)

	router := gin.Default()

	router.GET("/access", handler.GetTokens)
	router.POST("/refresh", handler.RefreshToken)

	if err := router.Run(cfg.ServerAddress + cfg.ServerPort); err != nil {
		log.Fatalf("Could not start API: %v", err)
	}
}
