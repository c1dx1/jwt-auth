package tests

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"jwt-auth/internal/models"
	"jwt-auth/internal/packages"
	"testing"
	"time"
)

func TestGenerateAccessToken(t *testing.T) {
	req := models.AccessRequest{GUID: "42342423", IP: "192.168.0.1", Iat: (time.Now()).UnixMilli()}

	tokens := packages.NewTokens()

	access, err := tokens.NewAccessToken(req, "3wr34r34f54g54gt4ver")
	assert.Nil(t, err)
	assert.NotNil(t, access)
	fmt.Println(access)
}

func TestEqualAccess(t *testing.T) {
	req := models.AccessRequest{GUID: "42342423", IP: "192.168.0.1", Iat: (time.Now()).Unix()}

	tokens := packages.NewTokens()

	access1, err := tokens.NewAccessToken(req, "3wr34r34f54g54gt4ver")
	assert.NoError(t, err)
	access2, err := tokens.NewAccessToken(req, "3wr34r34f54g54gt4ver")
	assert.Equal(t, access1, access2)
}

func TestGenerateRefreshToken(t *testing.T) {
	tokens := packages.NewTokens()

	refreshBase64, refreshHash, err := tokens.NewRefreshToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, refreshBase64)
	assert.NotEmpty(t, refreshHash)
	fmt.Println(refreshHash)
}
