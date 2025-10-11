package constants

import (
	"time"
)

const (
	day                                time.Duration = 24 * time.Hour
	defaultDurationForHostKeyInDays    time.Duration = 365
	defaultDurationForUserKeyInMinutes time.Duration = 30

	AppName        string = "ssh-keysign"
	ConfigFileName string = "config.yml"
	EtcDir         string = "/etc"
)

func DefaultDurationForHostKey() uint64 {
	return uint64((defaultDurationForHostKeyInDays * day).Seconds())
}

func DefaultDurationForUserKey() uint64 {
	return uint64((defaultDurationForUserKeyInMinutes * time.Minute).Seconds())
}
