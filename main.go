package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

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

//*****************************

func Login(c *gin.Context) {

	//************ Get user information from the db
	//w http.ResponseWriter, r *http.Request,

	db, err := sql.Open("postgres", psqlInfo)

	userInfo.Email = c.PostForm("email")
	userInfo.Passsword = c.PostForm("password")
	fmt.Println(" ")

	fmt.Println(userInfo.Email)
	fmt.Println(userInfo.Passsword)
	fmt.Println(" ")

	fmt.Printf(`email: %s  password: %s `, userInfo.Email, userInfo.Passsword)
	fmt.Println(" ")

	sqlStatement := `SELECT phrase FROM UserInfo WHERE email=$1 and password=$2;`
	row := db.QueryRow(sqlStatement, userInfo.Email, userInfo.Passsword)
	err = row.Scan(&userInfo.Phrase)
	if err != nil {

		w.WriteHeader(http.StatusUnauthorized)
		fmt.Println(row)
		fmt.Println(err.Error())
		return
	}

	jwtKey = []byte(userInfo.Phrase)

	fmt.Printf(`El valor de jwtKey es %s`, jwtKey)
	fmt.Println(" ")

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
	fmt.Println(" ")
	fmt.Printf(`El valor del tokenString: %s`, tokenString)
	fmt.Println(" ")
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Print(err.Error())
		fmt.Printf(`Error construyendo el Token %s`, err.Error())
		return
	}
	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself

	/*
		http.SetCookie(w, &http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})
	*/

	cookie := http.Cookie{
		Name:  "mycookie",
		Value: "prueba",
	}

	http.SetCookie(w, &cookie)

}

//*****************************

func GetAll(c *gin.Context) {

	db, err := sql.Open("postgres", psqlInfo)

	var (
		user  User
		users []User
	)

	rows, err := db.Query("SELECT id, name, lastname, email, role FROM UserInfo")
	if err != nil {
		fmt.Print(err.Error())
	}
	for rows.Next() {
		err = rows.Scan(&user.ID, &user.Name, &user.Lastname, &user.Email, &user.Role)
		users = append(users, user)
		if err != nil {
			fmt.Print(err.Error())
		}
	}
	defer rows.Close()
	c.JSON(http.StatusOK, gin.H{
		"result": users,
		"count":  len(users),
	})
}

func getOne(c *gin.Context) {

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
		result = gin.H{
			"result": nil,
			"count":  1,
			"error":  err,
		}
	} else {
		result = gin.H{
			"result": user,
			"count":  1,
		}
	}
	c.JSON(http.StatusOK, result)
}

func insertUser(c *gin.Context) {

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
	}
	_, err = stmt.Exec(name, lastname, email, phrase, password, role)
	if err != nil {
		fmt.Print(err.Error())
	}

	defer stmt.Close()
	name = fmt.Sprintf("%s, %s, %s", name, lastname, email)
	c.JSON(http.StatusOK, gin.H{
		"mesage": fmt.Sprint("succesfully created ", name),
	})
}

func updateUser(c *gin.Context) {

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
