package main

import (
	"fmt"

	"github.com/krish8learn/JWT_GO/http_server"
)

func main() {
	fmt.Println("Running the server")
	http_server.Server()
}
