package auth

import "net/mail"

// isValidEmail checks whether the provided string is an email.
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
