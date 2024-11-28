package types

import (
	"be-authentication-go/app/generated/auth"
	"context"
)

type AuthenticationService interface {
	AddUser(context.Context, *auth.AddUserReq) (*auth.AddUserRes, error)
	GetUserById(context.Context, *auth.GetUserByIdReq) (*auth.GetUserByIdRes, error)
	GetUserList(context.Context, *auth.GetUserListReq) (*auth.GetUserListRes, error)
	UpdateUser(context.Context, *auth.UpdateUserReq, int64) (*auth.UpdateUserRes, error)
	Login(context.Context, *auth.LoginReq) (*auth.LoginRes, error)
}
