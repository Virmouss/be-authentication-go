package utils

import (
	"be-authentication-go/app/model"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Seed(db *gorm.DB) {
	var count int64

	db.AutoMigrate([]model.User{})
	db.Model([]model.User{}).Count(&count)

	if count == 0 {
		CreateUserModel(db, "admin", "admin123")
	}
}

func CreateUserModel(db *gorm.DB, username string, password string) {

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("cant hash password: %v", err)
	}

	data := []model.User{
		{
			Username:  "admin",
			Password:  string(passwordHash),
			CreatedAt: time.Now().String(),
			UpdatedAt: time.Now().String(),
		},
	}
	if err := db.Create(&data).Error; err != nil {
		log.Fatalf("Could not seed User data: %v", err)
	}

}
