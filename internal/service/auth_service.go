package service

import (
	"context"
	"errors"
	"loggger/internal/model"
	"loggger/internal/repository"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidEmail = errors.New("Invalid email")
	ErrWeakPassword = errors.New("Password must > 8")
	ErrInvalidCreds = errors.New("Invalid credentials")
)

type AuthService interface {
	Register(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error)
	Login(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error)
}

type authService struct {
	userRepo  repository.UserRepository
	jwtSecret []byte
}

func NewAuthService(userRepo repository.UserRepository, jwtSecret []byte) AuthService {
	return &authService{
		userRepo:  userRepo,
		jwtSecret: jwtSecret,
	}
}

func (s *authService) Register(ctx context.Context, req model.AuthRequest) (*model.AuthResponse, error) {
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		return nil, ErrInvalidEmail
	}
	if len(req.Password) < 8 {
		return nil, ErrWeakPassword
	}
	hashed_pwd, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	user, err := s.userRepo.Create(ctx, req.Email, string(hashed_pwd))
	if err != nil {
		return nil, err
	}
	token, err := s.createToken(user.ID, user.Email)
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCreds
	}
	token, err := s.createToken(user.ID, user.Email)
	if err != nil {
		return nil, err
	}
	return &model.AuthResponse{Token: token}, nil
}

func (s *authService) createToken(id int64, email string) (string, error) {
	claims := &model.CustomClaims{
		UserID: id,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}
