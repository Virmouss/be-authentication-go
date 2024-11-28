package controller

import (
	"be-authentication-go/app/generated/auth"
	"be-authentication-go/app/middleware"
	"be-authentication-go/app/model"
	"context"
	"log"
	"net/http"
	"os"
	"regexp"
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
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client or Something Went Wrong"})
		return
	}

	if response.Message != "success" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": response.Message})
		return
	}

	token, err := GenerateJWT(response.Id, response.Role)
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

	var userInput model.EditInput

	err := ctx.ShouldBindJSON(&userInput)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !ValidatePassword(userInput.Password) {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Password must be Alphanumeric and symbols with minimum length 8 characters and maximum length 32 characters"})
		return
	}
	if userInput.Password != userInput.RePassword {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Password is not the same"})
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
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client or Something Went Wrong"})
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
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client or Something Went Wrong"})
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

func UpdateUserHTTP(ctx *gin.Context) {
	var userInput model.EditInput

	err := ctx.ShouldBindJSON(&userInput)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if userInput.Password != "" {
		if !ValidatePassword(userInput.Password) {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Password must be Alphanumeric and symbols with minimum length 8 characters and maximum length 32 characters"})
			return
		}
		if userInput.Password != userInput.RePassword {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Password is not the same"})
			return
		}
	}

	token_string := ctx.GetHeader("Authorization")

	authToken := strings.Split(token_string, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	tokenStr := authToken[1]

	// Parse and get claims from token
	claims := &model.Claims{}
	_, err = jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("API_KEY")), nil
	})
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	md := metadata.New(map[string]string{
		"auth": authToken[1],
	})

	request := auth.UpdateUserReq{}
	if userInput.Password != "" {
		request = auth.UpdateUserReq{
			Id:              userInput.Id,
			Username:        userInput.Username,
			CurrentPassword: userInput.CurrentPassword,
			Password:        userInput.Password,
			Role:            claims.Role,
		}
	} else {
		request = auth.UpdateUserReq{
			Id:       userInput.Id,
			Username: userInput.Username,
			Password: "",
			Role:     claims.Role,
		}
	}

	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)

	client, connnection, err := createGRPCClient()
	if err != nil {
		log.Print(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC service"})
		return
	}
	defer connnection.Close()

	response, err := client.UpdateUser(ctx_grpc, &request)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client or Something Went Wrong"})
		return
	}

	if response.Message != "Data Saved Successfully" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": response.Message})
		return
	}

	ctx.JSON(200, gin.H{"status": "User Updated"})

}

func GetUserListHTTP(ctx *gin.Context) {
	token_string := ctx.GetHeader("Authorization")

	authToken := strings.Split(token_string, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		ctx.AbortWithStatus(http.StatusUnauthorized)
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
	if claims.Role != "Super Admin" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized Access"})
		return
	}
	md := metadata.New(map[string]string{
		"auth": authToken[1],
	})

	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)

	request := auth.GetUserListReq{Role: claims.Role}

	client, connnection, err := createGRPCClient()
	if err != nil {
		log.Print(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC service"})
		return
	}
	defer connnection.Close()

	response, err := client.GetUserList(ctx_grpc, &request)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client or Something Went Wrong"})
		return
	}

	if response.TotalData == 0 {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "No User Found"})
		return
	}

	userList := []gin.H{}
	for _, user := range response.UserList {
		userList = append(userList, gin.H{
			"id":         user.Id,
			"username":   user.Username,
			"role":       user.Role,
			"updated_at": user.UpdatedAt,
			"created_at": user.CreatedAt,
		})
	}
	ctx.JSON(200, gin.H{
		"user_list":  userList,
		"total_data": response.TotalData,
	})
}

func ResetUserPassword(ctx *gin.Context) {

	token_string := ctx.GetHeader("Authorization")

	authToken := strings.Split(token_string, " ")
	if len(authToken) != 2 || authToken[0] != "Bearer" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		ctx.AbortWithStatus(http.StatusUnauthorized)
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
	if claims.Role != "Super Admin" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized Access"})
	}
	md := metadata.New(map[string]string{
		"auth": authToken[1],
	})

	var userInput model.EditInput
	err = ctx.ShouldBindJSON(&userInput)

	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	request := auth.UpdateUserReq{
		Id:       userInput.Id,
		Username: userInput.Username,
		Password: "123456",
		Role:     claims.Role,
	}

	ctx_grpc := metadata.NewOutgoingContext(context.Background(), md)

	client, connnection, err := createGRPCClient()
	if err != nil {
		log.Print(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to connect to gRPC service"})
		return
	}
	defer connnection.Close()

	response, err := client.UpdateUser(ctx_grpc, &request)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gRPC Client or Something Went Wrong"})
		return
	}

	if response.Message != "Data Saved Successfully" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": response.Message})
		return
	}

	ctx.JSON(200, gin.H{"status": "User Password Resetted"})

}

func createGRPCClient() (auth.AuthenticationClient, *grpc.ClientConn, error) {

	connection, err := grpc.NewClient(os.Getenv("GRPC_ADDRESS"), grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		return nil, nil, err
	}

	client := auth.NewAuthenticationClient(connection)

	return client, connection, nil

}

func GenerateJWT(id int64, role string) (string, error) {
	claims := &model.Claims{
		Id:   id,
		Role: role,
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

func ValidatePassword(password string) bool {
	passwordRegex := `^[a-zA-Z0-9!@#$%^&*(),.?":{}|<>_\-+=~` + "`" + `\[\]\\\/;']{8,32}$`

	re := regexp.MustCompile(passwordRegex)
	return re.MatchString(password)
}
