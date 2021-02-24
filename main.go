package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofiber/fiber"
	"github.com/gofiber/fiber/v2"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"

	"github.com/dgrijalva/jwt-go"

	_ "github.com/lib/pq"
)

//UserInfo user information
type UserInfo struct {
	Email     string
	Passsword string
	Phrase    string
}

var jwtKey []byte

//Claims vars
type Claims struct {
	UserEmail string `json:"email"`
	jwt.StandardClaims
}

var userInfo UserInfo
var w http.ResponseWriter

const (
	host     = "localhost"
	port     = 5432
	user     = "dbuser"
	password = "dbuserpassword"
	dbname   = "users"
)

//User information
type User struct {
	ID       int
	Name     string
	Lastname string
	Email    string
	Role     string
}

//Database connection parameters
var psqlInfo string = fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
	host, port, user, password, dbname)

//EvalToken check if the token is ok
func EvalToken(c *gin.Context) bool {
	// We can obtain the session token from the requests cookies, which come with every request
	tknStr, err := c.Cookie("token")

	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			c.Writer.WriteHeader(http.StatusUnauthorized) //w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		// For any other type of error, return a bad request status
		c.Writer.WriteHeader(http.StatusBadRequest) // w.WriteHeader(http.StatusBadRequest)
		return false
	}

	// Get the JWT string from the cookie
	//tknStr := t

	// Initialize a new instance of `Claims`
	claims := &Claims{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.Writer.WriteHeader(http.StatusUnauthorized)
			return false
		}
		c.Writer.WriteHeader(http.StatusBadRequest)
		return false
	}
	if !tkn.Valid {
		c.Writer.WriteHeader(http.StatusUnauthorized)
	}

	c.String(200, "Welcome %s:", claims.UserEmail)

	return true
}

//*****************************

//setTokens
func setTokens(email, phrase string, c *gin.Context) {

	jwtKey = []byte(phrase)

	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &Claims{
		UserEmail: userInfo.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//token := jwt.New(jwt.SigningMethodHS256)
	// Create the JWT string

	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		c.Writer.WriteHeader(http.StatusInternalServerError) //w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself

	c.SetCookie("accessToken", tokenString, 120, "/", "localhost", false, true)
	c.SetCookie("refreshToken", tokenString, 604800, "/", "localhost", false, true)

}

func middle() func(*gin.Context) error {
	return func(c *gin.Context) error {
		accessToken, err := c.Cookie("accesstoken")
		claims := new(Claims)

		token, err := jwt.ParseWithClaims(accessToken, claims,
			func(token *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			})

		if token.Valid {
			if claims.ExpiresAt < time.Now().Unix() {

				c.JSON(http.StatusUnauthorized, gin.H{
					"error":   true,
					"general": "Token Expired",
				})
			}
			
			
		} else if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				// this is not even a token, we should delete the cookies here

				//Clear cookies("accessToken", "refreshToken")
				c.SetCookie("accessToken", "none", -1, "/", "localhost", false, true)
				c.SetCookie("refreshToken", "none", -1, "/", "localhost", false, true)

				c.JSON(http.StatusForbidden, gin.H{
					"error":   true,
					"general": "StatusForbidden",
				})
				return errors.New("StatusForbidden")	

				

			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				// Token is either expired or not active yet
								
				return errors.New("StatusUnauthorized")

			} else {
				// cannot handle this token
				c.SetCookie("accessToken", "none", -1, "/", "localhost", false, true)
				c.SetCookie("refreshToken", "none", -1, "/", "localhost", false, true)

				return errors.New("StatusForbidden")
			}
		}

		//c.Locals("email", claims.UserEmail)
		c.Keys = {"email":claims.UserEmail}
		return c.Next()
	}
}

//refreshLogin function
func refreshLogin(email string, c *gin.Context) error {

	//************ Get user information from the db

	db, err := sql.Open("postgres", psqlInfo)

	sqlStatement := `SELECT phrase FROM UserInfo WHERE email=$1;`
	row := db.QueryRow(sqlStatement, userInfo.Email)
	err = row.Scan(&userInfo.Phrase)
	if err != nil {
		return err
	}

	//Create auth token and refresh token
	setTokens(userInfo.Email, userInfo.Phrase, c)

}

//Login function
func Login(c *gin.Context) {

	//************ Get user information from the db

	db, err := sql.Open("postgres", psqlInfo)
	userInfo.Email = c.PostForm("email")
	userInfo.Passsword = c.PostForm("password")

	sqlStatement := `SELECT phrase FROM UserInfo WHERE email=$1 and password=$2;`
	row := db.QueryRow(sqlStatement, userInfo.Email, userInfo.Passsword)
	err = row.Scan(&userInfo.Phrase)
	if err != nil {
		c.Writer.WriteHeader(http.StatusUnauthorized) //w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Create auth token and refresh token
	setTokens(userInfo.Email, userInfo.Phrase, c)

}

//GetAll function
func GetAll(c *gin.Context) {

	if !EvalToken(c) {
		return
	}

	db, err := sql.Open("postgres", psqlInfo)

	var (
		user  User
		users []User
	)

	rows, err := db.Query("SELECT id, name, lastname, email, role FROM UserInfo")
	if err != nil {
		c.Writer.WriteHeader(http.StatusNotFound)
		fmt.Print(err.Error())
		return
	}
	for rows.Next() {
		err = rows.Scan(&user.ID, &user.Name, &user.Lastname, &user.Email, &user.Role)
		users = append(users, user)
		if err != nil {
			c.Writer.WriteHeader(http.StatusNoContent)
			fmt.Print(err.Error())
			return
		}
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{
		"result": users,
		"count":  len(users),
	})
}

func getOne(c *gin.Context) {

	if !EvalToken(c) {
		return
	}

	db, err := sql.Open("postgres", psqlInfo)

	var (
		user   User
		result gin.H
	)

	id := c.Param("id")
	sqlStatement := `SELECT id, name, lastname, email, role FROM UserInfo WHERE id=$1;`
	row := db.QueryRow(sqlStatement, id)
	err = row.Scan(&user.ID, &user.Name, &user.Lastname, &user.Email, &user.Role)
	if err != nil {
		c.Writer.WriteHeader(http.StatusNoContent)
		result = gin.H{
			"result": nil,
			"count":  1,
			"error":  err,
		}
		return
	} else {
		result = gin.H{
			"result": user,
			"count":  1,
		}
	}
	c.JSON(http.StatusOK, result)
}

func insertUser(c *gin.Context) {

	if !EvalToken(c) {
		return
	}

	db, err := sql.Open("postgres", psqlInfo)

	name := c.PostForm("name")
	lastname := c.PostForm("lastname")
	email := c.PostForm("email")
	phrase := c.PostForm("phrase")
	password := c.PostForm("password")
	role := c.PostForm("role")

	stmt, err := db.Prepare("INSERT INTO UserInfo (name, lastname, email, phrase, password, role) VALUES ($1, $2, $3, $4, $5, $6)")
	if err != nil {
		fmt.Print(err.Error())
		c.Writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	_, err = stmt.Exec(name, lastname, email, phrase, password, role)
	if err != nil {
		fmt.Print(err.Error())
		c.Writer.WriteHeader(http.StatusNotAcceptable)
		return
	}

	defer stmt.Close()
	name = fmt.Sprintf("%s, %s, %s", name, lastname, email)
	c.JSON(http.StatusOK, gin.H{
		"mesage": fmt.Sprint("succesfully created ", name),
	})
}

func updateUser(c *gin.Context) {

	if !EvalToken(c) {
		return
	}

	db, err := sql.Open("postgres", psqlInfo)

	id := c.PostForm("id")
	name := c.PostForm("name")
	lastname := c.PostForm("lastname")
	email := c.PostForm("email")
	phrase := c.PostForm("phrase")
	password := c.PostForm("password")
	role := c.PostForm("role")

	stmt, err := db.Prepare("UPDATE UserInfo SET name= $1, lastname = $2, email= $3, phrase = $4, password= $5, role = $6 WHERE id= $7;")
	if err != nil {
		fmt.Println(err.Error())
		fmt.Printf("The user Id: %s was not modified", id)
	}
	_, err = stmt.Exec(name, lastname, email, phrase, password, role, id)
	if err != nil {
		fmt.Print(err.Error())
	}

	defer stmt.Close()
	name = fmt.Sprintf("%s, %s, %s, %s, %s, %s, %v", name, lastname, email, phrase, password, role, id)
	c.JSON(http.StatusOK, gin.H{
		"mesage": fmt.Sprint("succesfully updated to ", name),
	})
}

func deleteUser(c *gin.Context) {

	if !EvalToken(c) {
		return
	}

	db, err := sql.Open("postgres", psqlInfo)

	id := c.Param("id")
	stmt, err := db.Prepare("DELETE FROM UserInfo WHERE id= $1;")
	if err != nil {
		fmt.Print(err.Error())
	}
	_, err = stmt.Exec(id)

	if err != nil {
		fmt.Print(err.Error())
	}
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Successfully deleted user; %s", id),
	})
}

func main() {

	router := gin.Default()

	router.POST("/login", Login)           // **************  Get one user  **************
	router.GET("/all", GetAll)             // **************  Get all users  **************
	router.GET("/user/:id", getOne)        // **************  Get one user  **************
	router.POST("/user", insertUser)       // **************  Insert user  **************
	router.PUT("/user", updateUser)        // **************  Update user  **************
	router.DELETE("/user/:id", deleteUser) // **************  Delete user  **************

	router.Run(":3020")

}
