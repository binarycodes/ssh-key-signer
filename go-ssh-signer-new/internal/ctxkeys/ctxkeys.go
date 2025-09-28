package ctxkeys

import (
	"context"

	"github.com/spf13/viper"
)

type (
	viperKey struct{}
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
