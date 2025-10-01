package logging

import (
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type (
	LogLevel       string
	LogDestination string
)

const (
	LError LogLevel = "error"
	LWarn  LogLevel = "warn"
	LInfo  LogLevel = "info"
	LDebug LogLevel = "debug"
)

const (
	LStdErr LogDestination = "stderr"
	LStdOut LogDestination = "stdout"
	LFile   LogDestination = "file"
)

type Options struct {
	Level       LogLevel
	Destination LogDestination
	Sample      bool
}

func ParseLogLevel(s string) (LogLevel, error) {
	switch strings.ToLower(s) {
	case "error":
		return LError, nil
	case "warn":
		return LWarn, nil
	case "info":
		return LInfo, nil
	case "debug":
		return LDebug, nil
	default:
		return "", fmt.Errorf("invalid log level: %q (expected error|warn|info|debug)", s)
	}
}

func ParseLogDestination(s string) (LogDestination, error) {
	switch strings.ToLower(s) {
	case "stderr":
		return LStdErr, nil
	case "stdout":
		return LStdOut, nil
	case "file":
		return LFile, nil
	default:
		return "", fmt.Errorf("invalid log destination: %q (expected stderr|stdout|file)", s)
	}
}

func (d *LogDestination) UnmarshalText(text []byte) error {
	v, err := ParseLogDestination(string(text))
	if err != nil {
		return err
	}
	*d = v
	return nil
}

func Build(o Options) (logger *zap.Logger, cleanup func() error, err error) {
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	enc := zapcore.NewJSONEncoder(encCfg)

	var lvl zapcore.Level
	switch o.Level {
	case LError:
		lvl = zap.ErrorLevel
	case LWarn:
		lvl = zap.WarnLevel
	case LInfo:
		lvl = zap.InfoLevel
	case LDebug:
		lvl = zap.DebugLevel
	}
	atom := zap.NewAtomicLevelAt(lvl)

	var ws zapcore.WriteSyncer
	switch o.Destination {
	case LStdErr:
		ws = zapcore.AddSync(os.Stderr)
	case LStdOut:
		ws = zapcore.AddSync(os.Stdout)
	case LFile:
		path := "/var/log/ssh-keysign.log"
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, err
		}
		ws = zapcore.AddSync(f)
	}

	core := zapcore.NewCore(enc, ws, atom)
	if o.Sample {
		core = zapcore.NewSamplerWithOptions(core, 100, 10, 100)
	}

	logger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	cleanup = func() error {
		err := logger.Sync()
		return err
	}
	return logger, cleanup, nil
}
