package handler

import (
	"errors"
	"loggger/internal/model"
	"loggger/internal/repository"
	"loggger/internal/service"
	"net/http"

	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (a *AuthHandler) SignupHandler(c echo.Context) error {
	var req model.AuthRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid Request Payload")
	}

	res, err := a.authService.Register(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWeakPassword):
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		case errors.Is(err, repository.ErrUserAlreadyExists):
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		default:
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}
	return c.JSON(http.StatusCreated, res)
}

func (a *AuthHandler) LoginHandler(c echo.Context) error {
	var req model.AuthRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	res, err := a.authService.Login(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCreds):
			return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
		default:
			return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
		}
	}
	return c.JSON(http.StatusOK, res)
}
