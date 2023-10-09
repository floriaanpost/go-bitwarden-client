# Bitwarden for Go
This package uses the Bitwarden CLI to get bitwarden secrets.

It can be used in scripts where you need passwords/secrets but don't want to hardcode them in your code.

# How to install
1. [Install the bitwarden CLI](https://bitwarden.com/help/cli/)
2. Run `bw login` to login

That's it! You can now use this package to retreive passwords from code.

# Example usage
```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/floriaanpost/bitwarden_test/bitwarden"
	"golang.org/x/term"
)

const itemID = "b2bccebf-7ec2-436e-8d2c-ad4700783d83"

func main() {
	// start the Bitwarden server
	bw := bitwarden.New()
	defer bw.Close()

	// get your master password from the command line
	fmt.Printf("Enter your master password: ")
	masterPassword, err := term.ReadPassword(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	// unlock your vault
	if err := bw.Unlock(context.TODO(), string(masterPassword)); err != nil {
		fmt.Println("failed unlocking vault:", err)
		return
	}
	defer bw.Lock(context.TODO())

	// get a secure note
	note, err := bw.GetSecureNote(context.TODO(), itemID)
	if err != nil {
		fmt.Println("failed getting secure note:", err)
		return
	}
	fmt.Println(note)
}
```
