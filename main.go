package main

import (
	"be-authentication-go/app/controller"
	"be-authentication-go/app/db"
	"be-authentication-go/app/helper"
	"be-authentication-go/app/middleware"
	"be-authentication-go/app/services"
	"be-authentication-go/utils"
	"log"
	"net"
	"os"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

func main() {

	utils.LoadEnv()

	db, err := db.ConnectDB()
	utils.Seed(db)
	if err != nil {
		log.Fatal("failed to connect database", err)
	} else {
		log.Println("Connected to database")
	}

	helper.NewBlacklist()

	StartGRPCServer()
	StartGinServer()
}

func StartGRPCServer() {
	portNumber := os.Getenv("GRPC_PORT")
	lis, err := net.Listen("tcp", ":"+portNumber)
	if err != nil {
		log.Fatalf("gRPC fail to listen on port "+portNumber+" : %v", err)
	} else {
		log.Println("gRPC Starting...")

		grpcServer := grpc.NewServer()

		//register service
		authService := services.NewAuthenticationService()
		controller.NewGrpcAuthService(grpcServer, authService)

		go func() {
			log.Println("gRPC listening to port " + portNumber)
			if err := grpcServer.Serve(lis); err != nil {
				log.Fatalf("could not start grpc server: %v", err)
			}
		}()
	}
}

func StartGinServer() {
	hostName := os.Getenv("GIN_HOST")
	portNumber := os.Getenv("GIN_PORT")

	server := gin.Default()

	server.POST("/login", controller.LoginHTTP)
	server.POST("/signup", controller.AddUserHttp)
	server.POST("/logout", controller.LogoutHTTP)

	//protected
	protected := server.Group("/profile")

	protected.Use(middleware.AuthMiddleware)
	protected.GET("", controller.GetUserByIdHTTP)

	server.Run(hostName + ":" + portNumber)
}
