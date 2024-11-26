package middleware

import (
	"be-authentication-go/app/helper"
	"be-authentication-go/app/model"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var blacklist = helper.NewBlacklist()

func VerifyJWT(tokenStr string) (*model.Claims, error) {
	claims := &model.Claims{}

	if blacklist.IsTokenBlacklisted(tokenStr) {
		return nil, fmt.Errorf("token is blacklisted")
	}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("API_KEY")), nil
	})

	if err != nil {
		log.Println("Error during token parsing:", err)
		return nil, err
	}

	if !token.Valid {
		log.Println("Token is invalid")
		return nil, jwt.ErrTokenMalformed
	}
	//log.Println("Token is valid. Claims:", claims)
	return claims, nil

}

func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token missing"})
		c.Abort()
		return
	}

	authToken := strings.Split(authHeader, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	tokenStr := authToken[1]
	//fmt.Println(tokenStr)

	claims, err := VerifyJWT(tokenStr)
	if err != nil {
		fmt.Printf("Error : %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token",
		})
		c.Abort()
		return
	}

	// Save claims to the context for later use
	c.Set("user", claims.Id)
	c.Next()
}

func AddBlacklistToken(token string, exp time.Time) {
	blacklist.AddToken(token, exp)
}
