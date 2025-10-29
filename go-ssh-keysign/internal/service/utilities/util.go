package utilities

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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

func GenerateRandomNumberString(n int) string {
	digits := 10
	minNum := int(math.Pow10(digits - 1))
	maxNum := int(math.Pow10(digits)) - 1
	return strconv.Itoa(rand.Intn(maxNum-minNum+1) + minNum)
}

func GenerateRandomFileName() string {
	timestamp := time.Now().Format("20060102_15_04_05")
	random := GenerateRandomNumberString(5)
	return fmt.Sprintf("%s-%s", random, timestamp)
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
