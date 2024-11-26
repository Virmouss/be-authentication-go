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
	}

	return &response, nil
}
