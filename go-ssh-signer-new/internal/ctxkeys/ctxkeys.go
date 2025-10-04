package ctxkeys

import (
	"context"

	"github.com/spf13/viper"
	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/logging"
)

type (
	viperKey      struct{}
	loggerKey     struct{}
	logCleanupKey struct{}
	printerKey    struct{}
)

func WithViper(ctx context.Context, v *viper.Viper) context.Context {
	return context.WithValue(ctx, viperKey{}, v)
}

func ViperFrom(ctx context.Context) *viper.Viper {
	if v, ok := ctx.Value(viperKey{}).(*viper.Viper); ok && v != nil {
		return v
	}
	return viper.New()
}

func WithLogger(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

func LoggerFrom(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*zap.Logger); ok && l != nil {
		return l
	}
	return zap.NewNop()
}

func WithLogCleanup(ctx context.Context, cleanup func() error) context.Context {
	return context.WithValue(ctx, logCleanupKey{}, cleanup)
}

func CleanupFrom(ctx context.Context) func() error {
	if cl, ok := ctx.Value(logCleanupKey{}).(func() error); ok && cl != nil {
		return cl
	}
	return nil
}

func WithPrinter(ctx context.Context, printer *logging.Printer) context.Context {
	return context.WithValue(ctx, printerKey{}, printer)
}

func PrinterFrom(ctx context.Context) *logging.Printer {
	if cl, ok := ctx.Value(printerKey{}).(*logging.Printer); ok && cl != nil {
		return cl
	}
	return nil
}
