package repository

import (
	"context"
	"database/sql"
	"errors"
	"loggger/internal/model"
	"strings"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
}

type sqliteUserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &sqliteUserRepository{db: db}
}

func (r *sqliteUserRepository) Create(ctx context.Context, email, passwordHash string) (*model.User, error) {
	query := `INSERT INTO users (email, password_hash) VALUES (?, ?)`
	res, err := r.db.ExecContext(ctx, query, email, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return nil, ErrUserAlreadyExists
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &model.User{
		ID:    id,
		Email: email,
	}, nil
}

func (r *sqliteUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, password_hash, created_at FROM users WHERE email = ?`
	var user model.User
	if err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.PassHash, &user.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}
