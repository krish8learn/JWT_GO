package http_server

import (
	"log"
	"net/http"

	"github.com/krish8learn/JWT_GO/handlers"
)

func Server() {
	http.HandleFunc("/signin", handlers.Signin)
	http.HandleFunc("/welcome", handlers.Welcome)
	http.HandleFunc("/refresh", handlers.Refresh)

	log.Fatal(http.ListenAndServe(":8085", nil))
}
