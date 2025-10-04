package apperror

import (
	"context"
	"errors"
	"io"
	"net/http"
)

type (
	Kind       int
	HelpMethod func() error
)

const (
	KUnknown    Kind = iota
	KUsage           // bad flags/config
	KAuth            // 401/403
	KNetwork         // DNS/TLS
	KFileSystem      // read/write perms
	KCanceled        // context canceled/deadline
	KHttp            // http errors
)

type appError struct {
	Op      string // optional: "cert.IssueUser"
	Type    Kind
	OpError error
}

func (kind Kind) ExitCode() int {
	switch kind {
	case KUsage:
		return 2
	case KAuth:
		return 11
	case KCanceled:
		return 12
	case KNetwork:
		return 10
	case KFileSystem:
		return 13
	case KHttp:
		return 14
	default:
		return 1
	}
}

func (appErr *appError) Error() string {
	if appErr.Op != "" {
		return appErr.Op + ": " + appErr.OpError.Error()
	}
	return appErr.OpError.Error()
}

func (appErr *appError) Unwrap() error {
	return appErr.OpError
}

func ErrUsage(message string) error {
	appErr := errors.New(message)
	return &appError{Type: KUsage, OpError: appErr}
}

func ErrAuth(err error) error {
	return &appError{Type: KAuth, OpError: err}
}

func ErrNet(err error) error {
	// map std ctx errors to KCanceled early
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &appError{Type: KCanceled, OpError: err}
	}
	return &appError{Type: KNetwork, OpError: err}
}

func ErrFileSystem(err error) error {
	return &appError{Type: KFileSystem, OpError: err}
}

func ErrHTTP(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &appError{Type: KHttp, OpError: err}
	}
	err = errors.New(string(body))
	return &appError{Type: KHttp, OpError: err}
}

func Op(op string, err error) error {
	if err == nil {
		return nil
	}
	var appErr *appError
	if errors.As(err, &appErr) {
		return &appError{Op: op, Type: appErr.Type, OpError: appErr} // keep chain
	}
	return &appError{Op: op, Type: KUnknown, OpError: err}
}

func KindOf(err error) Kind {
	var appErr *appError
	if errors.As(err, &appErr) {
		return appErr.Type
	}
	return KUnknown
}
