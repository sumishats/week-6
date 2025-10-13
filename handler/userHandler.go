package handler

import (
	"fmt"
	"net/http"
	"practice/database"
	"practice/models"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type PageData struct { //store error message
	EmailInvalid string
	PassInvalid  string
}

type User struct { //store in user details
	Name     string
	Email    string
	Password string
}

type Claims struct { //it is used to stored user info and jwt token create
	UserID             uint   `json:"user_id"`
	Email              string `json:"email"`
	UserType           string `json:"user_type"`
	jwt.StandardClaims        //this is jwt token field expire and user like that
}

var jwtKey = []byte("SecretKey") //it is create secret key in jwt and it is  used to sign and varify token

// this func plain text password covert to hashed password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// check password hashes pass plain text match ano noka
func CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// generate jwt generate a new token
func GenerateJWT(userID uint, email, userType string) (string, error) {
	claims := Claims{ //user details
		UserID:   userID,
		Email:    email,
		UserType: userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(), //24 hour expire
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey) //secret key
}

// indexpage
func IndexPage(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

// signup func
func Signup(c *gin.Context) {
	c.HTML(http.StatusOK, "signup.html", nil)
}

// signuppost
func SignupPost(c *gin.Context) {
	name := strings.TrimSpace(c.Request.FormValue("name")) //unwanted space oke maaattii
	email := strings.TrimSpace(c.Request.FormValue("email"))
	password := strings.TrimSpace(c.Request.FormValue("password"))

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate") //cache zero aki
	c.Header("Expires", "0")

	//validation
	if name == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "name is required"})
		return
	}

	if email == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "email is required"})
		return
	}

	if password == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "password is required"})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := database.Db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{"error": "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{"error": "Error processing password"})
		return
	}

	// Create user
	user := models.User{Name: name, Email: email, Password: hashedPassword}
	if database.Db == nil {
		fmt.Println("Database connection is nil!")
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{"error": "Database error"})
		return
	}

	result := database.Db.Create(&user)
	if result.Error != nil {
		fmt.Println(result.Error)
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{"error": "Failed to create user"})
		return
	}

	c.Redirect(http.StatusSeeOther, "/login")

}

// login func
func Login(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate") //header avoid cache zero
	c.Header("Expires", "0")

	//check if user already login and valid jwt
	tokenString, err := c.Cookie("jwt_token")
	if err == nil && tokenString != "" {
		//validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err == nil && token.Valid && claims.UserType == "user" { //user thanne ann token ind ok aneki home pass
			c.Redirect(http.StatusSeeOther, "/home")
			return
		}
	}

	c.HTML(200, "login.html", nil)
}

// func login post
func LoginPost(c *gin.Context) {
	email := strings.TrimSpace(c.Request.FormValue("emailName"))
	password := strings.TrimSpace(c.Request.FormValue("passwordName"))

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	//validation
	if email == "" {
		c.HTML(200, "login.html", PageData{EmailInvalid: "Email is required"})
		return
	}
	if password == "" {
		c.HTML(200, "login.html", PageData{PassInvalid: "Password is required"})
		return
	}

	//find user for database
	var user models.User
	result := database.Db.Where("email=?", email).First(&user)
	if result.Error != nil || result.RowsAffected == 0 {
		c.HTML(200, "login.html", PageData{EmailInvalid: "user not found"})
		return
	}

	//check password hashed ano noka 
	if !CheckPassword(user.Password, password) {
		c.HTML(200, "login.html", PageData{PassInvalid: "password is invalid"})
		return
	}

	//generate jwt token with userid,email
	token, err := GenerateJWT(user.ID, user.Email, "user")
	if err != nil {
		c.HTML(http.StatusInternalServerError, "login.html", PageData{PassInvalid: "error generating token"})
		return

	}

	//store jwt in cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("jwt_token", token, 24*60*60, "/", "", false, true) //set cookie 24 hour

	c.Redirect(http.StatusSeeOther, "/home")

}

// home method
func HomeMethod(c *gin.Context) {
	//get user info from  jwt claims set by middleware
	userID, exists := c.Get("user_id")
	if !exists {
		c.Redirect(303, "/login")
		return
	}
	email, _ := c.Get("email")

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")

	c.HTML(200, "index.html", gin.H{
		"user_id": userID,
		"email":   email,
	})
}

// logout
func Logout(c *gin.Context) {
	//clear jwt cookie
	c.SetCookie("jwt_token", "", -1, "/", "", false, true)
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.Redirect(303, "/login")

}
