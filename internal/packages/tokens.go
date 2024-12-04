package packages

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"jwt-auth/internal/models"
	"time"
)

type Tokens struct{}

func NewTokens() *Tokens { return &Tokens{} }

func (t *Tokens) NewAccessToken(req models.AccessRequest, jwtSecretKey string) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": req.GUID,
		"ip":   req.IP,
		"iat":  req.Iat,
		"exp":  time.Unix(req.Iat, 0).Add(time.Hour).Unix(),
	})

	accessTokenString, err := accessToken.SignedString([]byte(jwtSecretKey))
	if err != nil {
		return "", fmt.Errorf("packages/tokens.go: newaccesstoken: sing token: %w", err)
	}

	return accessTokenString, nil
}

func (t *Tokens) NewRefreshToken() (string, string, error) {
	refresh := make([]byte, 32)

	_, err := rand.Read(refresh)
	if err != nil {
		return "", "", fmt.Errorf("packages/tokens.go: newrefreshtoken: rand.read : %w", err)
	}

	refreshBase64 := base64.StdEncoding.EncodeToString(refresh)
	refreshHash, err := bcrypt.GenerateFromPassword([]byte(refreshBase64), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("packages/tokens.go: newrefreshtoken: bcrypt.GenerateFromPassword: %w", err)
	}

	return refreshBase64, string(refreshHash), nil
}

func (t *Tokens) ValidateRefreshToken(storedRefresh, reqRefresh string) error {
	err := bcrypt.CompareHashAndPassword([]byte(storedRefresh), []byte(reqRefresh))
	if err != nil {
		return fmt.Errorf("packages/tokens.go: validate refresh token: wrong password: %w", err)
	}
	return nil
}

func (t *Tokens) ValidateToken(access string, secretKey []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(access, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("packages/tokens.go: validatetoken: unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("packages/tokens.go: validatetoken: invalid token")
}
