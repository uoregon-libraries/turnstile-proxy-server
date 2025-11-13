// Package main is our tiny static page handler to serve up whatever's in the
// protected and public subdirs
package main

import (
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	var r = gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.Redirect(302, "/public")
	})

	r.NoRoute(func(c *gin.Context) {
		c.Data(404, "text/html; charset=utf-8", []byte(`404 page not found. Go to <a href="/public">public</a>.`))
	})

	r.Static("/protected", "./protected")
	r.Static("/public", "./public")

	log.Println("Listening on :8080...")
	var err = r.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
