package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var jwtKey = []byte("SecretKey") // In production, use environment variable  and this is the secretkey sign and verify token

type Claims struct {
	UserID   uint   `json:"user_id"`
	Email    string `json:"email"`
	UserType string `json:"user_type"` // "user" or "admin"
	jwt.StandardClaims
}

func JWTAuthMiddleware() gin.HandlerFunc { //define gin middleware func
	return func(c *gin.Context) { //token valid continue alleki stop

		//check token n authorization in header
		authHeader := c.GetHeader("Authorization")

		var tokenString string
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer")

		} else {
			//header token ileki  browser cookie name jwt_token ano nokaa
			cookie, err := c.Cookie("jwt_token")
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "no token provided"})
				c.Abort()
				return
			}
			tokenString = cookie

		} 
		//token indeki ath valid ano check chyum
		// Parse and validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid { //token missing ann valid alla indei error
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("user_type", claims.UserType)

		c.Next() //go to home

	}
}

// UserAuthMiddleware ensures only users can access
func UserAuthMiddleware() gin.HandlerFunc { //middileware run before main route handler check modify and request
	return func(c *gin.Context) {
		userType, exists := c.Get("user_type")
		if !exists || userType != "user" {
			c.JSON(http.StatusForbidden, gin.H{"error": "user access required"})
			c.Abort() //stop
			return
		}
		c.Next()
	}

}

// adminauthmiddleware ensure only admin can access
func AdminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userType, exists := c.Get("user_type")
		if !exists || userType != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}

}
