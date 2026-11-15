package auth

import "errors"

var ErrUserAlreadyExists = errors.New("user already exists")
var ErrIncorrectLoginData = errors.New("incorrect login or password")
var ErrUserNotFound = errors.New("user not found")
