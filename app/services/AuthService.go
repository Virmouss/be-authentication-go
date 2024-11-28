package services

import (
	"be-authentication-go/app/db"
	"be-authentication-go/app/generated/auth"
	"be-authentication-go/app/model"
	"context"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthenticationService struct {
	db *gorm.DB
}

func NewAuthenticationService() *AuthenticationService {
	db, err := db.ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	return &AuthenticationService{db: db}
}

func (s *AuthenticationService) Login(ctx context.Context, loginReq *auth.LoginReq) (*auth.LoginRes, error) {

	var userFound model.User
	s.db.Where("username=?", loginReq.Username).Find(&userFound)

	err := bcrypt.CompareHashAndPassword([]byte(userFound.Password), []byte(loginReq.Password))

	if err != nil {
		response := auth.LoginRes{
			Message: "Password is invalid",
			Id:      0,
		}
		return &response, err
	}

	response := auth.LoginRes{
		Message: "success",
		Id:      int64(userFound.Id),
		Role:    userFound.Role,
	}

	return &response, nil
}

func (s *AuthenticationService) AddUser(ctx context.Context, req *auth.AddUserReq) (*auth.AddUserRes, error) {

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	saved := model.User{
		Username:  req.Username,
		Password:  string(passwordHash),
		Role:      "User",
		CreatedAt: time.Now().String(),
		UpdatedAt: time.Now().String(),
	}

	result := s.db.Model(&model.User{}).Create(&saved)

	if result.Error != nil {
		response := auth.AddUserRes{
			Id:        int64(saved.Id),
			Message:   "Failed to Save Data",
			CreatedAt: saved.CreatedAt,
		}
		return &response, result.Error
	}

	response := auth.AddUserRes{
		Id:        int64(saved.Id),
		Message:   "Data saved successfully",
		CreatedAt: saved.CreatedAt,
	}

	return &response, nil

}

func (s *AuthenticationService) GetUserById(ctx context.Context, req *auth.GetUserByIdReq) (*auth.GetUserByIdRes, error) {
	var result model.User

	if err := s.db.First(&result, req.Id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, err
		}
		return nil, err
	}

	response := auth.GetUserByIdRes{
		Id:       int64(result.Id),
		Username: result.Username,
		Role:     result.Role,
	}

	return &response, nil
}

func (s *AuthenticationService) UpdateUser(ctx context.Context, req *auth.UpdateUserReq, claims_id int64) (*auth.UpdateUserRes, error) {
	var user model.User
	var result *gorm.DB
	role := req.Role
	pass := req.Password

	response := auth.UpdateUserRes{}

	if role == "Super Admin" {
		if pass == "" {
			result = s.db.Model(&user).Where("id = ?", req.Id).Updates(map[string]interface{}{
				"username":   req.Username,
				"updated_at": time.Now().String(),
			})

		} else {
			passwordHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}
			result = s.db.Model(&user).Where("id = ?", req.Id).Updates(map[string]interface{}{
				"username":   req.Username,
				"password":   passwordHash,
				"updated_at": time.Now().String(),
			})
		}
	} else {

		if claims_id != int64(req.Id) {
			response = auth.UpdateUserRes{
				Message: "Not Admin",
				Id:      0,
			}
			return &response, nil
		}

		s.db.Where("id=?", req.Id).Find(&user)

		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword))
		if err != nil {
			response := auth.UpdateUserRes{
				Message: "Current Password is invalid",
				Id:      0,
			}
			return &response, err
		}

		if pass == "" {
			result = s.db.Model(&user).Where("id = ?", req.Id).Updates(map[string]interface{}{
				"username":   req.Username,
				"updated_at": time.Now().String(),
			})

		} else {
			passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
			if err != nil {
				return nil, err
			}

			result = s.db.Model(&user).Where("id = ?", req.Id).Updates(map[string]interface{}{
				"username":   req.Username,
				"password":   passwordHash,
				"updated_at": time.Now().String(),
			})
		}
	}

	if result.Error != nil {
		response = auth.UpdateUserRes{
			Message: "Username is not unique",
			Id:      0,
		}
		return &response, result.Error
	}

	if result.RowsAffected == 0 {
		response = auth.UpdateUserRes{
			Message: "User not found",
			Id:      0,
		}

		return &response, result.Error
	}

	response = auth.UpdateUserRes{
		Message: "Data Saved Successfully",
		Id:      req.Id,
	}
	return &response, nil
}

func (s *AuthenticationService) GetUserList(ctx context.Context, req *auth.GetUserListReq) (*auth.GetUserListRes, error) {
	var users []model.User

	if req.Role != "Super Admin" {
		return nil, nil
	}

	if err := s.db.Find(&users).Error; err != nil {
		log.Printf("Error querying database: %v", err)
		return nil, err
	}

	var userList []*auth.GetUserListRes_User
	for _, user := range users {
		userList = append(userList, &auth.GetUserListRes_User{
			Id:        int64(user.Id),
			Username:  user.Username,
			Role:      user.Role,
			UpdatedAt: user.UpdatedAt,
			CreatedAt: user.CreatedAt,
		})
	}

	response := auth.GetUserListRes{
		UserList:  userList,
		TotalData: int32(len(userList)),
	}
	return &response, nil

}
