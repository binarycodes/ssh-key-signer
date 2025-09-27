package constants

import (
	"fmt"
	"time"
)

const (
	day                                time.Duration = 24 * time.Hour
	defaultDurationForHostKeyInDays    time.Duration = 365
	defaultDurationForUserKeyInMinutes time.Duration = 30

	AppName        string = "ssh-keysign"
	ConfigFileName string = "config.yml"
)

func DefaultDurationForHostKey() uint64 {
	fmt.Println("for host")
	return uint64((defaultDurationForHostKeyInDays * day).Seconds())
}

func DefaultDurationForUserKey() uint64 {
	fmt.Println("for user")
	return uint64((defaultDurationForUserKeyInMinutes * time.Minute).Seconds())
}
