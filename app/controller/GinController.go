package controller

import (
	"be-authentication-go/app/generated/auth"
	"be-authentication-go/app/middleware"
	"be-authentication-go/app/model"
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

//var blacklist = helper.NewBlacklist()

func LoginHTTP(ctx *gin.Context) {

	var authInput model.AuthInput

	err := ctx.ShouldBindJSON(&authInput)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, connnection, err := createGRPCClient()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC service"})
		return
	}
	defer connnection.Close()

	request := &auth.LoginReq{
		Username: authInput.Username,
		Password: authInput.Password,
	}

	response, err := client.Login(context.Background(), request)

	if err != nil {
		log.Print(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client"})
		return
	}

	if response.Message != "success" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": response.Message})
		return
	}

	token, err := GenerateJWT(response.Id)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "failed to generate token"})
	}

	ctx.JSON(200, gin.H{
		"token": token,
	})

}

func LogoutHTTP(ctx *gin.Context) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization token missing"})
		return
	}

	authToken := strings.Split(authHeader, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		return
	}

	tokenStr := authToken[1]

	// Parse and get claims from token (optional)
	claims := &model.Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("API_KEY")), nil
	})
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	// Add the token to the blacklist
	//log.Printf("Exp time blacklist: %v", claims.ExpiresAt.Time)
	middleware.AddBlacklistToken(tokenStr, claims.ExpiresAt.Time)

	ctx.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

func AddUserHttp(ctx *gin.Context) {

	var userInput model.User

	err := ctx.ShouldBindJSON(&userInput)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	client, connnection, err := createGRPCClient()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC service"})
		return
	}
	defer connnection.Close()

	request := &auth.AddUserReq{
		Username: userInput.Username,
		Password: userInput.Password,
	}

	response, err := client.AddUser(context.Background(), request)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client"})
		return
	}

	if response.Message != "Data saved successfully" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": response.Message})
		return
	}

	ctx.JSON(200, gin.H{"status": "User Created"})

}

func GetUserByIdHTTP(ctx *gin.Context) {
	var userInput model.User

	err := ctx.ShouldBindJSON(&userInput)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token_string := ctx.GetHeader("Authorization")

	authToken := strings.Split(token_string, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	md := metadata.New(map[string]string{
		"auth":    authToken[1],
		"API_KEY": os.Getenv("API_KEY"),
	})

	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)

	request := auth.GetUserByIdReq{
		Id: int64(userInput.Id),
	}

	client, connnection, err := createGRPCClient()
	if err != nil {
		log.Print(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC service"})
		return
	}
	defer connnection.Close()

	response, err := client.GetUserById(ctx_grpc, &request)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client"})
		return
	}

	if response.Username == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	ctx.JSON(200, gin.H{
		"Id":       response.Id,
		"Username": response.Username,
	})

}

func createGRPCClient() (auth.AuthenticationClient, *grpc.ClientConn, error) {

	connection, err := grpc.NewClient(os.Getenv("GRPC_ADDRESS"), grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		return nil, nil, err
	}

	client := auth.NewAuthenticationClient(connection)

	return client, connection, nil

}

func GenerateJWT(id int64) (string, error) {
	claims := &model.Claims{
		Id: id,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(os.Getenv("API_KEY")))
	if err != nil {
		return "", err
	}

	//log.Println("Generated JWT Token:", signedToken)
	return signedToken, nil
	//return token.SignedString([]byte(os.Getenv("API_KEY")))
}
