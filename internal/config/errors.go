package config

import "fmt"

type ValidationError struct {
	Field   string
	Message string
}

func NewValidationError(field, msg string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: msg,
	}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf(`ValidationError: Field="%s" Message="%s"`, e.Field, e.Message)
}
