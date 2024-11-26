package model

type User struct {
	Id        uint   `json:"id" gorm:"primary_key"`
	Username  string `json:"username" gorm:"unique"`
	Password  string `json:"password"`
	CreatedAt string
	UpdatedAt string
}
