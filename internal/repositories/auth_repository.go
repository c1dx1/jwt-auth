package repositories

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"jwt-auth/internal/models"
)

type AuthRepository struct {
	db *pgxpool.Pool
}

func NewAuthRepository(db *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{db: db}
}

func (r *AuthRepository) Save(ctx context.Context, accept models.AccessRequest, refresh string) error {
	db, err := r.db.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("jwt repo: savetoken: acquire db error: %w", err)
	}
	defer db.Release()

	_, err = db.Exec(ctx, "INSERT INTO tokens(guid, iat, ip, refresh_hash) VALUES ($1, $2, $3, $4)",
		accept.GUID, accept.Iat, accept.IP, refresh)
	if err != nil {
		return fmt.Errorf("jwt repo: savetoken: insert error: %w", err)
	}

	return nil
}

func (r *AuthRepository) UpdateTokens(ctx context.Context, req models.RefreshRequest, id int, newRefreshHash string) error {
	db, err := r.db.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("jwt repo: savetoken: acquire db error: %w", err)
	}
	defer db.Release()

	_, err = db.Exec(ctx, "UPDATE tokens SET iat = $1, ip = $2, refresh_hash = $3 WHERE id = $4",
		req.Iat, req.IP, newRefreshHash, id)
	if err != nil {
		return fmt.Errorf("jwt repo: savetoken: update error: %w", err)
	}
	return nil
}

func (r *AuthRepository) GetTokenPayload(ctx context.Context, aGuid string, aIat int64) (int, string, error) {
	db, err := r.db.Acquire(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("jwt repo: get user data: acquire db error: %w", err)
	}
	defer db.Release()

	var refreshHash string
	var id int
	err = db.QueryRow(ctx, "SELECT id, refresh_hash FROM tokens WHERE guid = $1 AND iat = $2", aGuid, aIat).
		Scan(&id, &refreshHash)
	if err != nil {
		return 0, "", fmt.Errorf("jwt repo: get user data: get token payload: query row error: %w", err)
	}
	return id, refreshHash, nil
}

func (r *AuthRepository) GetEmail(ctx context.Context, guid string) (string, error) {
	db, err := r.db.Acquire(ctx)
	if err != nil {
		return "", fmt.Errorf("jwt repo: get user data: acquire db error: %w", err)
	}
	defer db.Release()

	var email string
	err = db.QueryRow(ctx, "SELECT email FROM users WHERE guid = $1", guid).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("jwt repo: get user data: get user data: query row error: %w", err)
	}

	return email, nil
}
