package main

import (
	"database/sql"
	"log"
	"loggger/internal/handler"
	"loggger/internal/model"
	"loggger/internal/repository"
	"loggger/internal/service"
	"os"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	_ "modernc.org/sqlite"
)

func main() {
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	db, err := sql.Open("sqlite", "app.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP	
		);
	`)

	userRepo := repository.NewUserRepository(db)
	authService := service.NewAuthService(userRepo, jwtSecret)
	authHandler := handler.NewAuthHandler(authService)

	e := echo.New()
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())

	authGroup := e.Group("/auth")
	authGroup.POST("/signup", authHandler.SignupHandler)
	authGroup.POST("/login", authHandler.LoginHandler)

	apiGroup := e.Group("/api")
	apiGroup.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: jwtSecret,
		NewClaimsFunc: func(c echo.Context) jwt.Claims {
			return new(model.CustomClaims)
		},
	}))
	e.Logger.Fatal(e.Start(":8080"))
}
