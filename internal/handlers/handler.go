package handlers

import (
	"github.com/gin-gonic/gin"
	"jwt-auth/internal/models"
	"jwt-auth/internal/services"
	"log"
	"strings"
	"time"
)

type Handler struct {
	AuthService *services.AuthService
}

func NewHandler(authService *services.AuthService) *Handler {
	return &Handler{AuthService: authService}
}

func (h *Handler) GetTokens(c *gin.Context) {
	var req models.AccessRequest

	if err := c.ShouldBindQuery(&req); err != nil {
		log.Printf("access: %w", err)
		c.JSON(400, gin.H{"error: ": "Bad Request"})
		return
	}

	req.IP = c.ClientIP()
	req.Iat = (time.Now()).Unix()

	tokens, err := h.AuthService.GetTokens(req)
	if err != nil {
		log.Printf("access: %w", err)
		c.JSON(500, gin.H{"error: ": "Internal Server Error"})
		return
	}

	c.JSON(200, gin.H{"tokens": tokens})
}

func (h *Handler) RefreshToken(c *gin.Context) {
	var req models.RefreshRequest

	var err error
	refreshToken, err := c.Cookie("rt")
	if err != nil {
		log.Printf("refresh: %w", err)
		c.JSON(400, gin.H{"error: ": "Bad Request"})
		return
	}
	req.RefreshToken = strings.ReplaceAll(refreshToken, " ", "+")

	req.AccessToken, err = c.Cookie("at")
	if err != nil {
		log.Printf("refresh: %w", err)
		c.JSON(400, gin.H{"error: ": "Bad Request"})
		return
	}

	req.IP = c.ClientIP()
	req.Iat = (time.Now()).Unix()

	tokens, err := h.AuthService.RefreshTokens(req)
	if err != nil {
		log.Printf("refresh: %w", err)
		c.JSON(500, gin.H{"error: ": "Internal Server Error"})
		return
	}

	c.JSON(200, gin.H{"tokens": tokens})
}
