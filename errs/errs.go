package errs

import (
	"strings"
	"time"
)

// Error struct easyier error return to the api and is used
// accross the project.
type Error struct {
	Err        error     `json:"-"`
	StatusCode int       `json:"_"`
	Message    string    `json:"message,omitempty"`
	Path       string    `json:"path,omitempty"`
	Timestamp  time.Time `json:"timestamp,omitempty"`
}

// Implementation of the error interface for this struct
func (e *Error) Error() string {
	res := ""
	var ce error = e
	cnt := 0
	for ce != nil {
		if cnt > 0 {
			res += strings.Repeat("\t", cnt)
			res += "| "
		}
		if cee, ok := ce.(*Error); ok {
			res += cee.Message
			ce = cee.Err
		} else {
			res += ce.Error()
			break
		}
		res += "\n"
		cnt++
	}
	return res
}

// New creates a new error
func New(message string) *Error {
	return &Error{Message: message, Timestamp: time.Now()}
}

// New creates a new error with error code
func NewWithCode(message string, code int) *Error {
	return &Error{StatusCode: code, Message: message, Timestamp: time.Now()}
}

// Add the message to an error, if cannot or message already exists,
// wrap it with another one with the new path
// Wrap returns nil if err == nil
func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		if e.Message == "" {
			e.Message = message
			return e
		}
	}
	return &Error{Err: err, Message: message}
}

// WrapWithError wraps err inside an existing error
func WrapWithError(err error, err2 error) error {
	if err == nil {
		return nil
	}
	if e, ok := err2.(*Error); ok {
		e.Err = err
		return e
	} else {
		return &Error{
			Err:     err,
			Message: err2.Error(),
		}
	}
}

// Add the path to an error, if cannot or path already exists,
// wrap it with another one with the new path
// WrapPath returns nil if err == nil
func WrapPath(err error, path string) error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		if e.Path == "" {
			e.Path = path
			return e
		}
	}
	return &Error{Err: err, Path: path}
}

// Collaps create a new error by putting the first path found and the
// first message found inside the error.
func Collaps(e error) error {
	if e == nil {
		return nil
	}
	res := &Error{}
	var ce error = e

	// find first path
	for res.Path == "" || res.Message == "" || res.StatusCode == 0{
		if ce.Error() != "" {
			res.Message = ce.Error()
		}
		if c, ok := ce.(*Error); ok {
			if c.Path != "" {
				res.Path = c.Path
			}
			if c.StatusCode != 0 {
				res.StatusCode = c.StatusCode
			}
			ce = c.Err
		} else {
			break
		}
	}
	return res
}
