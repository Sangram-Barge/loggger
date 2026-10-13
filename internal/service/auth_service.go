package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"loggger/internal/model"
	"loggger/internal/repository"
)

var (
	ErrInvalidCreds = errors.New("invalid email or password")
	ErrWeakPassword = errors.New("password must be at least 8 characters")
)

type AuthService interface {
	Register(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error)
	Login(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error)
	Logout(ctx context.Context, userID int64) error
	ValidateTokenVersion(ctx context.Context, userID int64, tokenVersion int) bool
}

type authService struct {
	userRepo  repository.UserRepository
	jwtSecret []byte
}

func NewAuthService(userRepo repository.UserRepository, jwtSecret []byte) AuthService {
	return &authService{userRepo: userRepo, jwtSecret: jwtSecret}
}

func (s *authService) Register(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error) {
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if len(req.Password) < 8 {
		return nil, ErrWeakPassword
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.Create(ctx, req.Email, string(hashed))
	if err != nil {
		return nil, err
	}

	token, err := s.createToken(user.ID, user.Email, user.TokenVersion)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{Token: token}, nil
}

func (s *authService) Login(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error) {
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))

	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrInvalidCreds
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCreds
	}

	token, err := s.createToken(user.ID, user.Email, user.TokenVersion)
	if err != nil {
		return nil, err
	}

	return &model.AuthResponse{Token: token}, nil
}

func (s *authService) Logout(ctx context.Context, userID int64) error {
	return s.userRepo.IncrementTokenVersion(ctx, userID)
}

func (s *authService) ValidateTokenVersion(ctx context.Context, userID int64, tokenVersion int) bool {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return false
	}
	return user.TokenVersion == tokenVersion
}

func (s *authService) createToken(userID int64, email string, tokenVersion int) (string, error) {
	claims := &model.CustomClaims{
		UserID:       userID,
		Email:        email,
		TokenVersion: tokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}
