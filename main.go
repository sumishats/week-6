package main

import (
	"fmt"
	"os"

	"practice/database"
	"practice/handler"
	"practice/middleware"
	"practice/models"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// gin gorm use chyth oru admin user ulla oru web application ann create chythikune
func main() {
	var err error

	dsn := "user=postgres password=sumisha@2006 dbname=users host=localhost port=5432 sslmode=disable"

	database.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{}) //database gorm use chyth connect chythu

	if err != nil {
		fmt.Println("failed connect to database", err)
		os.Exit(1) //enthelum err indeki aa program avde stop cheyan vendi ann os package ulla oru func ann athil zero allath eth num anekilum program stop cheyanam
	}

	database.Db.AutoMigrate(&models.User{}) //table already indeki ok ileki automatic ayitt create  chyum
	database.Db.AutoMigrate(&models.Admin{})

	router := gin.Default()                 //gin create 
	router.LoadHTMLGlob("templates/*.html") //connect html page generate chyth
	router.Static("/static", "./static")    //static file gin lott aki

	// Public routes (no authentication required)
	router.GET("/", handler.IndexPage)
	router.POST("/", handler.IndexPage)
	router.GET("/signup", handler.Signup)
	router.POST("/signuppost", handler.SignupPost)
	router.GET("/login", handler.Login)
	router.POST("/loginpost", handler.LoginPost)
	router.GET("/adminlogin", handler.Adminlogin)
	router.POST("/adminloginpost", handler.AdminLoginPost)

	//protected user route with authentication
	userRoutes := router.Group("/")
	userRoutes.Use(middleware.JWTAuthMiddleware())  //check jwt token store cookie and token missing ano expire ano  and token ok anekil continue
	userRoutes.Use(middleware.UserAuthMiddleware()) //check user type is user thane ano noka
	{
		userRoutes.GET("/home", handler.HomeMethod)
		userRoutes.POST("/logout", handler.Logout)
	}

	//protected admin routes
	adminRoutes := router.Group("/")
	adminRoutes.Use(middleware.JWTAuthMiddleware())
	adminRoutes.Use(middleware.AdminAuthMiddleware())
	{
		adminRoutes.GET("/admin", handler.AdminPage)
		adminRoutes.GET("/adminlogout", handler.AdminLogout)
		adminRoutes.GET("/searchusers", handler.Search)
		adminRoutes.POST("/deleteuser/:id", handler.DeleteUser)
		adminRoutes.GET("/edituser/:id", handler.EditUser)
		adminRoutes.POST("/updateuser/:id", handler.UpdateUser)
		adminRoutes.GET("/createuser", handler.CreateUserPage)
		adminRoutes.POST("/adduser", handler.AddNewUser)
	}

	fmt.Println("server start on:8080")
	router.Run(":8080")

}
