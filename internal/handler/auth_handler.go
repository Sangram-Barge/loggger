package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"

	"loggger/internal/model"
	"loggger/internal/repository"
	"loggger/internal/service"
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
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request payload")
	}

	res, err := a.authService.Register(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrWeakPassword):
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		case errors.Is(err, repository.ErrUserAlreadyExists):
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		default:
			c.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, "An error occurred during registration")
		}
	}

	injectCookie(c, res.Token)
	return c.JSON(http.StatusCreated, map[string]string{"message": "User registered successfully"})
}

func (a *AuthHandler) LoginHandler(c echo.Context) error {
	var req model.AuthRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request payload")
	}

	res, err := a.authService.Login(c.Request().Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCreds):
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid email or password")
		default:
			c.Logger().Error(err)
			return echo.NewHTTPError(http.StatusInternalServerError, "An error occurred during login")
		}
	}

	injectCookie(c, res.Token)
	return c.JSON(http.StatusOK, map[string]string{"message": "Login successful"})
}

func (a *AuthHandler) LogoutHandler(c echo.Context) error {
	// If the user sends a valid token, increment their database token version
	if token, ok := c.Get("user").(*jwt.Token); ok {
		if claims, ok := token.Claims.(*model.CustomClaims); ok {
			_ = a.authService.Logout(c.Request().Context(), claims.UserID)
		}
	}

	// Expire the cookie on client
	cookie := new(http.Cookie)
	cookie.Name = "access_token"
	cookie.Value = ""
	cookie.Expires = time.Unix(0, 0)
	cookie.MaxAge = -1
	cookie.HttpOnly = true
	cookie.Secure = c.Scheme() == "https"
	cookie.SameSite = http.SameSiteStrictMode
	cookie.Path = "/"
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

func (a *AuthHandler) MeHandler(c echo.Context) error {
	token, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Token not found in request context")
	}

	claims, ok := token.Claims.(*model.CustomClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token claims structure")
	}

	return c.JSON(http.StatusOK, map[string]any{
		"user_id": claims.UserID,
		"email":   claims.Email,
	})
}

// TokenVersionMiddleware rejects requests if the token version is stale
func (a *AuthHandler) TokenVersionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token, ok := c.Get("user").(*jwt.Token)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "Missing token")
		}

		claims, ok := token.Claims.(*model.CustomClaims)
		if !ok {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid claims")
		}

		if !a.authService.ValidateTokenVersion(c.Request().Context(), claims.UserID, claims.TokenVersion) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Session expired or logged out")
		}

		return next(c)
	}
}

func injectCookie(c echo.Context, token string) {
	cookie := new(http.Cookie)
	cookie.Name = "access_token"
	cookie.Value = token
	cookie.Expires = time.Now().Add(15 * time.Minute)
	cookie.HttpOnly = true
	cookie.Secure = c.Scheme() == "https"
	cookie.SameSite = http.SameSiteStrictMode
	cookie.Path = "/"
	c.SetCookie(cookie)
}
