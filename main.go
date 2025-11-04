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

func main() {
	var err error

	dsn := "user=postgres password=sumisha@2006 dbname=users host=localhost port=5432 sslmode=disable"

	database.Db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		fmt.Println("failed connect to database", err)
		os.Exit(1)
	}

	database.Db.AutoMigrate(&models.User{})
	database.Db.AutoMigrate(&models.Admin{})

	router := gin.Default()
	router.LoadHTMLGlob("templates/*.html")
	router.Static("/static", "./static")

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
	userRoutes.Use(middleware.JWTAuthMiddleware())
	userRoutes.Use(middleware.UserAuthMiddleware())
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
		//adminRoutes.GET("/searchusers/:query", handler.Search) -->option

		adminRoutes.POST("/deleteuser/:id", handler.DeleteUser)
		adminRoutes.GET("/edituser/:id", handler.EditUser)
		adminRoutes.POST("/updateuser/:id", handler.UpdateUser)
		adminRoutes.GET("/createuser", handler.CreateUserPage)
		adminRoutes.POST("/adduser", handler.AddNewUser)
	}

	fmt.Println("server start on:8080")
	router.Run(":8080")

}
