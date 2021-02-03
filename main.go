package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	Id       int
	Name     string
	Lastname string
	Email    string
	Role     string
}

/*

func oneUser(id int) {

	db, err := sql.Open("mysql", "dbuser:dbuserpassword@tcp(127.0.0.1:3306)/users")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var user User
	row := db.QueryRow("SELECT id, name, lastname, email, role FROM UsersInfo where Id = ?;", id)
	err = row.Scan(&user.Id, &user.Name, &user.Lastname, &user.Email, &user.Role)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", user)
}

func allUsers() {
	db, err := sql.Open("mysql", "dbuser:dbuserpassword@tcp(127.0.0.1:3306)/users")
	if err != nil {
		log.Fatal(err)
	}
	res, err := db.Query("SELECT id, name, lastname, email, role FROM UsersInfo")
	defer db.Close()

	var user User
	for res.Next() {
		err := res.Scan(&user.Id, &user.Name, &user.Lastname, &user.Email, &user.Role)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%v\n", user)
	}

}

*/

func main() {

	db, err := sql.Open("mysql", "dbuser:dbuserpassword@tcp(127.0.0.1:3306)/users")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	router := gin.Default()

	router.GET("/user/:id", func(c *gin.Context) {
		var (
			user   User
			result gin.H
		)
		id := c.Param("id")
		row := db.QueryRow("SELECT id, name, lastname, email, role FROM UsersInfo WHERE Id = ?;", id)
		err = row.Scan(&user.Id, &user.Name, &user.Lastname, &user.Email, &user.Role)
		if err != nil {
			result = gin.H{
				"result": nil,
				"count":  1,
			}
		} else {
			result = gin.H{
				"result": user,
				"count":  1,
			}
		}
		c.JSON(http.StatusOK, result)

	})

	router.GET("/all", func(c *gin.Context) {

		var (
			user  User
			users []User
		)
		rows, err := db.Query("SELECT id, name, lastname, email, role FROM UsersInfo;")
		if err != nil {
			fmt.Print(err.Error())
		}
		for rows.Next() {
			err = rows.Scan(&user.Id, &user.Name, &user.Lastname, &user.Email, &user.Role)
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
	})

	router.POST("/user", func(c *gin.Context) {
		var buffer bytes.Buffer
		name := c.PostForm("name")
		lastname := c.PostForm("lastname")
		email := c.PostForm("email")
		phrase := c.PostForm("phrase")
		password := c.PostForm("password")
		role := c.PostForm("role")
		stmt, err := db.Prepare("INSERT INTO UsersInfo (name, lastname, email, phrase, password, role) VALUES (?,?,?,?,?,?)")
		if err != nil {
			fmt.Print(err.Error())
		}
		_, err = stmt.Exec(name, lastname, email, phrase, password, role)
		if err != nil {
			fmt.Print(err.Error())
		}

		buffer.WriteString(name)
		buffer.WriteString(" ")
		buffer.WriteString(lastname)
		buffer.WriteString(" ")
		buffer.WriteString(email)
		buffer.WriteString(" ")
		buffer.WriteString(phrase)
		buffer.WriteString(" ")
		buffer.WriteString(password)
		buffer.WriteString(" ")
		buffer.WriteString(role)
		defer stmt.Close()
		name = buffer.String()
		c.JSON(http.StatusOK, gin.H{
			"mesage": fmt.Sprint("%s succesfully created", name),
		})
	})

	router.PUT("/user", func(c *gin.Context) {
		var buffer bytes.Buffer
		id := c.PostForm("id")
		name := c.PostForm("name")
		lastname := c.PostForm("lastname")
		email := c.PostForm("email")
		phrase := c.PostForm("phrase")
		password := c.PostForm("password")
		role := c.PostForm("role")
		stmt, err := db.Prepare("UPDATE UsersInfo SET name= ?, lastname = ?, email= ?, phrase = ?, password= ?, role = ? WHERE id= ?;")
		if err != nil {
			fmt.Println(err.Error())
			fmt.Printf("The user Id: %s was not modified", id)
		}
		_, err = stmt.Exec(name, lastname, email, phrase, password, role, id)
		if err != nil {
			fmt.Print(err.Error())
		}
		buffer.WriteString(name)
		buffer.WriteString(" ")
		buffer.WriteString(lastname)
		buffer.WriteString(" ")
		buffer.WriteString(email)
		buffer.WriteString(" ")
		buffer.WriteString(phrase)
		buffer.WriteString(" ")
		buffer.WriteString(password)
		buffer.WriteString(" ")
		buffer.WriteString(role)
		defer stmt.Close()
		name = buffer.String()
		c.JSON(http.StatusOK, gin.H{
			"mesage": fmt.Sprint("succesfully updated to %s ", name),
		})

	})

	router.DELETE("/user/:id", func(c *gin.Context) {
		id := c.Param("id")
		stmt, err := db.Prepare("DELETE FROM UsersInfo WHERE id= ?;")
		if err != nil {
			fmt.Print(err.Error())
		}
		_, err = stmt.Exec(id)
		fmt.Printf("Inside DELETE using 's' parameter with the Id: %s ", id)
		fmt.Printf("Inside DELETE using 'v' parameter with the Id: %v ", id)
		if err != nil {
			fmt.Print(err.Error())
		}
		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Successfully deleted user; %s", id),
		})
	})

	router.Run(":3020")

}
