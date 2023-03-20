package config

import "fmt"

// ValidationError --
type ValidationError struct {
	Field   string
	Message string
}

// NewValidationError --
func NewValidationError(field, msg string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: msg,
	}
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf(`ValidationError: Field="%s" Message="%s"`, e.Field, e.Message)
}
