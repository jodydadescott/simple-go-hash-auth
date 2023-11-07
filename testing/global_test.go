package testing

import (
	"testing"

	"github.com/jodydadescott/simple-go-hash-auth/client"
	"github.com/jodydadescott/simple-go-hash-auth/server"
)

func TestNonce1(t *testing.T) {

	s := server.New(&server.Config{
		Secret: "abc123",
	})

	defer s.Shutdown()

	c := client.New(&client.Config{
		Secret: "abc123",
	})

	request := s.NewRequest()

	err := c.ProcessRequest(request)
	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

	token, err := s.GetTokenFromRequest(request)
	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

	err = s.ValidateToken(token.Token)
	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

}

func TestNonce2(t *testing.T) {

	s := server.New(&server.Config{
		Secret: "jk3434",
	})

	defer s.Shutdown()

	c := client.New(&client.Config{
		Secret: "abc123",
	})

	request := s.NewRequest()

	err := c.ProcessRequest(request)
	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

	_, err = s.GetTokenFromRequest(request)
	if err == nil {
		t.Fatalf("Err was expected")
	}

	// err = s.ValidateToken(token.Token)
	// if err != nil {
	// 	t.Fatalf("Unexpected err %s", err)
	// }

}

func TestNonce3(t *testing.T) {

	s := server.New(&server.Config{
		Secret: "abc123",
	})

	defer s.Shutdown()

	c := client.New(&client.Config{
		Secret: "abc123",
	})

	request := s.NewRequest()

	err := c.ProcessRequest(request)
	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

	_, err = s.GetTokenFromRequest(request)
	if err != nil {
		t.Fatalf("Unexpected err %s", err)
	}

	err = s.ValidateToken("random_junk")
	if err == nil {
		t.Fatalf("Err was expected")
	}

}
