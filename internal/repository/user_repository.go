package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"loggger/internal/model"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)

type UserRepository interface {
	Create(ctx context.Context, email, passwordHash string) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByID(ctx context.Context, id int64) (*model.User, error)
	IncrementTokenVersion(ctx context.Context, id int64) error
}

type sqliteUserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &sqliteUserRepository{db: db}
}

func (r *sqliteUserRepository) Create(ctx context.Context, email, passwordHash string) (*model.User, error) {
	query := `INSERT INTO users (email, password_hash, token_version) VALUES (?, ?, 1)`
	res, err := r.db.ExecContext(ctx, query, email, passwordHash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return nil, ErrUserAlreadyExists
		}
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &model.User{
		ID:           id,
		Email:        email,
		TokenVersion: 1,
	}, nil
}

func (r *sqliteUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	query := `SELECT id, email, password_hash, token_version, created_at FROM users WHERE email = ?`
	var user model.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.TokenVersion, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *sqliteUserRepository) GetByID(ctx context.Context, id int64) (*model.User, error) {
	query := `SELECT id, email, password_hash, token_version, created_at FROM users WHERE id = ?`
	var user model.User
	err := r.db.QueryRowContext(ctx, query, id).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.TokenVersion, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *sqliteUserRepository) IncrementTokenVersion(ctx context.Context, id int64) error {
	query := `UPDATE users SET token_version = token_version + 1 WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
