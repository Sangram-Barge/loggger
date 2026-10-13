package model

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type User struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	TokenVersion int       `json:"token_version"`
	CreatedAt    time.Time `json:"created_at"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token,omitempty"`
}

type CustomClaims struct {
	UserID       int64  `json:"user_id"`
	Email        string `json:"email"`
	TokenVersion int    `json:"token_version"`
	jwt.RegisteredClaims
}
