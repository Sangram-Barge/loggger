package handler

import (
	"loggger/internal/model"
	"loggger/internal/repository"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	userRepo repository.UserRepository
}

func NewUserHandler(repo repository.UserRepository) *UserHandler {
	return &UserHandler{
		userRepo: repo,
	}
}

func (u *UserHandler) me(c echo.Context) error {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Token no found")
	}
	claims, ok := token.Claims.(*model.CustomClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"user_id": claims.UserID,
		"email":   claims.Email,
	})
}
