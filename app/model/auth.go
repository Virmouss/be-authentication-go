package model

import "github.com/golang-jwt/jwt/v5"

type AuthInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Claims struct {
	Id int64 `json:"id"`
	jwt.RegisteredClaims
}
