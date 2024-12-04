package services

import (
	"context"
	"fmt"
	"jwt-auth/config"
	"jwt-auth/internal/models"
	"jwt-auth/internal/packages"
	"jwt-auth/internal/repositories"
	"time"
)

type AuthService struct {
	cfg       config.Config
	repo      repositories.AuthRepository
	tokens    *packages.Tokens
	emailChan chan models.EmailChan
}

func NewAuthService(cfg config.Config, repo repositories.AuthRepository, tokens *packages.Tokens, emailChan chan models.EmailChan) *AuthService {
	return &AuthService{cfg: cfg, repo: repo, tokens: tokens, emailChan: emailChan}
}

func (s *AuthService) GetTokens(req models.AccessRequest) (models.Tokens, error) {
	access, err := s.tokens.NewAccessToken(req, s.cfg.JWTSecretKey)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: gettokens: newaccess: %w", err)
	}

	refreshBase64, refreshHash, err := s.tokens.NewRefreshToken()
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: gettokens: newrefresh: %w", err)
	}

	err = s.repo.Save(context.Background(), req, refreshHash)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: gettokens: save: %w", err)
	}

	return models.Tokens{
		AccessToken:  access,
		RefreshToken: refreshBase64,
	}, nil
}

func (s *AuthService) RefreshTokens(req models.RefreshRequest) (models.Tokens, error) {
	id, err := s.ValidateClaims(&req)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: refreshtokens: validate claims: %w", err)
	}

	newAccess, err := s.tokens.NewAccessToken(models.AccessRequest{
		GUID: req.GUID,
		Iat:  req.Iat,
		IP:   req.IP,
	}, s.cfg.JWTSecretKey)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: refreshtokens: newaccess: %w", err)
	}

	newRefresh, newRefreshHash, err := s.tokens.NewRefreshToken()
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: refreshtokens: newrefresh: %w", err)
	}

	err = s.repo.UpdateTokens(context.Background(), req, id, newRefreshHash)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("services/auth_service.go: refreshtokens: save: %w", err)
	}

	return models.Tokens{AccessToken: newAccess, RefreshToken: newRefresh}, nil
}

func (s *AuthService) ValidateClaims(req *models.RefreshRequest) (int, error) {
	oldMapClaims, err := s.tokens.ValidateToken(req.AccessToken, []byte(s.cfg.JWTSecretKey))
	if err != nil {
		return 0, fmt.Errorf("services/auth_service.go: validateclaims: validatetoken: %w", err)
	}

	id, storedRefreshHash, err := s.repo.GetTokenPayload(context.Background(), oldMapClaims["guid"].(string), int64(oldMapClaims["iat"].(float64)))
	if err != nil {
		return 0, fmt.Errorf("services/auth_service.go: validateclaims: getpayload: %w", err)
	}

	err = s.tokens.ValidateRefreshToken(storedRefreshHash, req.RefreshToken)
	if err != nil {
		return 0, fmt.Errorf("services/auth_service.go: validateclaims: validaterefresh: %w", err)
	}

	req.GUID = oldMapClaims["guid"].(string)

	if req.IP != oldMapClaims["ip"].(string) {
		err = s.SendEmail(req.IP, req.GUID)
		if err != nil {
			return 0, fmt.Errorf("services/auth_service.go: sendemail: %w", err)
		}
	}
	return id, nil
}

func (s *AuthService) SendEmail(ip, guid string) error {
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelCtx()

	email, err := s.repo.GetEmail(ctx, guid)
	if err != nil {
		return fmt.Errorf("services/auth_service.go: sendemail: %w", err)
	}
	s.emailChan <- models.EmailChan{To: email, IP: ip}

	return nil
}
