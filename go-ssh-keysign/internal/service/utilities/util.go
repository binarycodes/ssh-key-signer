package utilities

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"binarycodes/ssh-keysign/internal/apperror"
)

func NormalizePath(p string) (string, error) {
	path := p

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	if trimmed, found := strings.CutPrefix(p, "~"); found {
		return filepath.Join(home, trimmed), nil
	}

	if trimmed, found := strings.CutPrefix(p, "$HOME"); found {
		return filepath.Join(home, trimmed), nil
	}

	/* allow expansion of other environment variables */
	return os.ExpandEnv(path), nil
}

// The parameter is expected to be an abolute file path
func GetCertificateFilePath(fp string) (string, error) {
	normalized, err := NormalizePath(fp)
	if err != nil {
		return "", apperror.ErrFileSystem(err)
	}

	dir := filepath.Dir(normalized)
	basename := filepath.Base(normalized)
	extension := filepath.Ext(normalized)

	nameWithoutExtension := strings.TrimSuffix(basename, extension)

	certFileName := fmt.Sprintf("%s-cert%s", nameWithoutExtension, extension)
	path, err := filepath.Abs(filepath.Join(dir, certFileName))
	if err != nil {
		return "", apperror.ErrFileSystem(err)
	}

	return path, nil
}
