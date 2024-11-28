package model

type User struct {
	Id        uint   `json:"id" gorm:"primary_key"`
	Role      string `json:"role"`
	Username  string `json:"username" gorm:"unique"`
	Password  string `json:"password"`
	CreatedAt string
	UpdatedAt string
}
