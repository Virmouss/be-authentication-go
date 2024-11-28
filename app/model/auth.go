package model

import "github.com/golang-jwt/jwt/v5"

type AuthInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type EditInput struct {
	Id         int64  `json:"id"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	RePassword string `json:"repassword"`
}

type Claims struct {
	Id   int64  `json:"id"`
	Role string `json:"role"`
	jwt.RegisteredClaims
}
