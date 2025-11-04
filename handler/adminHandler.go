package handler

import (
	"net/http"
	"practice/database"
	"practice/models"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

type Admin struct {
	Email    string
	Password string
}

func Adminlogin(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0") 

	//check if admin already login  or browser cookie jwt token indo enn
	tokenString, err := c.Cookie("jwt_token")
	if err == nil && tokenString != "" { 
		//validate token
		claims := Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		//admin ann already login chyth aneki admin page vidum loginpage cheyathe
		if err == nil && token.Valid && claims.UserType == "admin" {
			c.Redirect(http.StatusSeeOther, "/admin")
			return
		}

	}
	
	c.HTML(200, "adminLogin.html", nil)
}


func AdminLoginPost(c *gin.Context) {

	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0") 

	email := strings.TrimSpace(c.Request.FormValue("adminEmail"))
	password := strings.TrimSpace(c.Request.FormValue("adminPassword"))

	//validation
	if email == "" {
		c.HTML(400, "adminLogin.html", PageData{EmailInvalid: "email is requred"})
		return
	}

	if password == "" {
		c.HTML(400, "adminLogin.html", PageData{PassInvalid: "password is required"})
		return
	}

	//find admin in database
	var admin models.Admin
	result := database.Db.Where("email=?", email).First(&admin)
	if result.Error != nil || result.RowsAffected == 0 {
		c.HTML(404, "adminLogin.html", PageData{EmailInvalid: "Admin not found"})
		return
	}

	// Check password (Note: In production, admin passwords should also be hashed)
	if password != admin.Password {
		c.HTML(400, "adminLogin.html", PageData{PassInvalid: "Invalid password"})
		return
	}

	// Generate JWT token for admin
	token, err := GenerateJWT(admin.ID, admin.Email, "admin")
	if err != nil {
		c.HTML(http.StatusInternalServerError, "adminLogin.html", PageData{PassInvalid: "Error generating token"})
		return
	}

	//set jwt in cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("jwt_token", token, 24*60*60, "/", "", false, true) //24 hour

	c.Redirect(303, "/admin")
}

// adminpage
func AdminPage(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate") 
	c.Header("Expires", "0")                                       

	//get admin information from jwt claims (set by middleware)
	adminEmail, _ := c.Get("email")

	
	//fetch all users in db
	var users []models.User
	database.Db.Find(&users) 

	c.HTML(200, "admin.html", gin.H{ //render admin html page data safely
		"users":       users,
		"admin_email": adminEmail,
	})

}

// adminlogout
func AdminLogout(c *gin.Context) {
	// Clear JWT cookie rest cache
	c.SetCookie("jwt_token", "", -1, "/", "", false, true)
	c.Header("Cache-Control", "no-cache,no-store,must-revalidate")
	c.Header("Expires", "0")
	c.Redirect(303, "/adminlogin")
}

// adminsearch func
func Search(c *gin.Context) {
	var users []models.User                   
	searchQuery := c.DefaultQuery("query", "") //search text from url query params

	if searchQuery != "" { //email name noki user edukunu
		database.Db.Where("name ILIKE ? OR email ILIKE ?", "%"+searchQuery+"%", "%"+searchQuery+"%").Find(&users)
	} else {
		database.Db.Find(&users) //ellam user fetch cheyum
	}

	c.HTML(200, "admin.html", gin.H{
		"users": users,
	})

}

// delete user
func DeleteUser(c *gin.Context) {
	userID := c.Param("id")

	//convert string id into unit
	id, err := strconv.ParseUint(userID, 10, 32)
	if err != nil {
		c.JSON(400, gin.H{"error": "user not found"})
		return
	}

	//delete user
	result := database.Db.Delete(&models.User{}, uint(id)) 
	if result.Error != nil {
		c.JSON(500, gin.H{"error": "failed to delete user"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(404, gin.H{"error": "user not found"}) //user table row ileki err
		return
	}

	c.Redirect(303, "/admin") 
}

// edit user
func EditUser(c *gin.Context) {
	var user models.User    //user data
	userID := c.Param("id") //user id

	if err := database.Db.Where("id=?", userID).First(&user).Error; err != nil { //user id vech db noki user kittileki
		c.JSON(404, gin.H{"error": "user not found"})
		return
	}
	c.HTML(200, "edituser.html", gin.H{
		"users": user,
	})

}

// update user
func UpdateUser(c *gin.Context) {
	var user models.User
	userID := c.Param("id")

	if err := database.Db.Where("id = ?", userID).First(&user).Error; err != nil { //user databse indo nokii
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	name := strings.TrimSpace(c.PostForm("name")) //start end space remove chyth
	email := strings.TrimSpace(c.PostForm("email"))
	password := strings.TrimSpace(c.PostForm("password"))

	// Validate input
	if name == "" || email == "" {
		c.JSON(400, gin.H{"error": "Name and email are required"})
		return
	}

	user.Name = name
	user.Email = email

	// Only update password if provided hashed pass akum
	if password != "" {
		hashedPassword, err := HashPassword(password)
		if err != nil {
			c.JSON(500, gin.H{"error": "Error processing password"})
			return
		}
		user.Password = hashedPassword
	}

	if err := database.Db.Save(&user).Error; err != nil { //update chytha user info db akan apo valla issue vanna error
		c.JSON(500, gin.H{"error": "Failed to update user"})
		return
	}

	c.Redirect(303, "/admin")
}

// create user for admin
func CreateUserPage(c *gin.Context) {
	c.HTML(200, "createuser.html", nil)
}

// add new user
func AddNewUser(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("name"))
	email := strings.TrimSpace(c.PostForm("email"))
	password := strings.TrimSpace(c.PostForm("password"))

	// Validate input
	if name == "" || email == "" || password == "" {
		c.JSON(400, gin.H{"error": "All fields are required"})
		return
	}

	// Check if user already exists
	var existingUser models.User
	if err := database.Db.Where("email = ?", email).First(&existingUser).Error; err == nil {
		c.JSON(400, gin.H{"error": "User already exists"})
		return
	}

	// Hash password
	hashedPassword, err := HashPassword(password)
	if err != nil {
		c.JSON(500, gin.H{"error": "Error processing password"})
		return
	}

	user := models.User{ //user details /data
		Name:     name,
		Email:    email,
		Password: hashedPassword,
	}

	if err := database.Db.Create(&user).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	c.Redirect(303, "/admin")

}
