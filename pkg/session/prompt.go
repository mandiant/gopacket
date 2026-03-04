package session

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
)

// EnsurePassword prompts for a password if one is not present and other auth methods are not used.
func EnsurePassword(creds *Credentials) error {
	if creds.Password != "" || creds.Hash != "" {
		return nil
	}
	
	if creds.UseKerberos && os.Getenv("KRB5CCNAME") != "" {
		return nil
	}
	
	fmt.Printf("Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Newline
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	
	creds.Password = string(bytePassword)
	return nil
}
