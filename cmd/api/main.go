package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "modernc.org/sqlite"

	"loggger/internal/handler"
	"loggger/internal/model"
	"loggger/internal/repository"
	"loggger/internal/service"
)

func main() {
	rawSecret := os.Getenv("JWT_SECRET")
	if len(rawSecret) < 32 {
		log.Println("WARNING: JWT_SECRET should be at least 32 characters")
		if len(rawSecret) == 0 {
			rawSecret = "dev-secret-key-must-be-changed-in-production-12345"
		}
	}
	jwtSecret := []byte(rawSecret)

	db, err := sql.Open("sqlite", "app.db")
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	// Ensure token_version column exists
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			token_version INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP	
		);
	`
	if _, err := db.Exec(createTableQuery); err != nil {
		log.Fatalf("failed to execute migrations: %v", err)
	}

	userRepo := repository.NewUserRepository(db)
	authService := service.NewAuthService(userRepo, jwtSecret)
	authHandler := handler.NewAuthHandler(authService)

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{
			"http://localhost:3000",
			"http://localhost:5173",
			"http://127.0.0.1:5500",
		},
		AllowCredentials: true,
		AllowHeaders: []string{
			echo.HeaderOrigin,
			echo.HeaderContentType,
			echo.HeaderAccept,
			echo.HeaderAuthorization,
			"X-CSRF-Token",
		},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
	}))

	// CSRF with Skipper for public auth endpoints
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper: func(c echo.Context) bool {
			p := c.Path()
			return p == "/auth/login" || p == "/auth/signup" || p == "/auth/logout"
		},
		TokenLookup:    "header:X-CSRF-Token",
		CookieName:     "_csrf",
		CookieSameSite: http.SameSiteStrictMode,
		CookieHTTPOnly: false,
		CookiePath:     "/",
	}))

	// Public auth routes
	authGroup := e.Group("/auth")
	authGroup.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(20)))
	authGroup.POST("/signup", authHandler.SignupHandler)
	authGroup.POST("/login", authHandler.LoginHandler)

	// Protected routes (JWT verification + Version check)
	jwtMiddleware := echojwt.WithConfig(echojwt.Config{
		SigningKey:  jwtSecret,
		TokenLookup: "cookie:access_token,header:Authorization:Bearer ",
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(model.CustomClaims)
		},
	})

	// Logout route (requires JWT to identify which user is logging out)
	authGroup.POST("/logout", authHandler.LogoutHandler, jwtMiddleware)

	apiGroup := e.Group("/api")
	apiGroup.Use(jwtMiddleware)
	apiGroup.Use(authHandler.TokenVersionMiddleware) // Blocks stale/logged-out tokens immediately
	apiGroup.GET("/me", authHandler.MeHandler)

	e.Logger.Fatal(e.Start(":8080"))
}
