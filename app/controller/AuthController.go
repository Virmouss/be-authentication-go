package controller

import (
	"be-authentication-go/app/generated/auth"
	"be-authentication-go/app/middleware"
	"be-authentication-go/app/types"
	"context"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type AuthenticationController struct {
	authService types.AuthenticationService
	auth.UnimplementedAuthenticationServer
}

func NewGrpcAuthService(grpc *grpc.Server, authService types.AuthenticationService) {
	gRPCHandler := &AuthenticationController{
		authService: authService,
	}

	auth.RegisterAuthenticationServer(grpc, gRPCHandler)
}

func (h *AuthenticationController) Login(ctx context.Context, loginReq *auth.LoginReq) (*auth.LoginRes, error) {

	service_response, err := h.authService.Login(ctx, loginReq)

	if err != nil {
		return service_response, err
	}

	return service_response, nil

}

func (h *AuthenticationController) AddUser(ctx context.Context, req *auth.AddUserReq) (*auth.AddUserRes, error) {

	service_response, err := h.authService.AddUser(ctx, req)

	if err != nil {
		return service_response, err
	}

	return service_response, nil
}

func (h *AuthenticationController) GetUserById(ctx context.Context, req *auth.GetUserByIdReq) (*auth.GetUserByIdRes, error) {

	md, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metada")
	}

	authHeader := md["auth"]
	if len(authHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing auth token")
	}
	//log.Printf("Md Auth:%v", authHeader[0])
	claims, err := middleware.VerifyJWT(authHeader[0])

	if err != nil {
		return nil, status.Errorf((codes.Unauthenticated), "invalid token: %v", err)
	}
	log.Printf("Fetching User Data for Id: %v", claims.ID)

	service_response, err := h.authService.GetUserById(ctx, req)

	if err != nil {
		return service_response, err
	}

	return service_response, nil
}
