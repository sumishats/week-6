package models

import "gorm.io/gorm"

type User struct{ //user details 
	gorm.Model

	Name string
	Email string
	Password string

}

type Admin struct{ //admin details
	gorm.Model
	Email string
	Password string
}