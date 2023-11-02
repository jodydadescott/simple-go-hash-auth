package main

import (
	"fmt"

	auth "github.com/jodydadescott/simple-go-hash-auth"
)

func main() {

	err := run()
	if err != nil {
		fmt.Println(err.Error())
	}

}

func run() error {

	s := auth.NewServer(&auth.Config{
		Secret: "abc123",
	})

	c := auth.NewClient(&auth.Config{
		Secret: "abc123",
	})

	auth := s.NewAuth()

	err := c.Update(auth)
	if err != nil {
		return err
	}

	err = s.PutAuth(auth)
	if err != nil {
		return err
	}

	err = s.ValidateToken(auth.Token)
	if err != nil {
		return err
	}

	s.Shutdown()

	return nil
}
