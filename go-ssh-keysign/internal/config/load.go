package config

import (
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

func decoderHook() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapstructure.TextUnmarshallerHookFunc(),
	)
}

func Load(v *viper.Viper) (Config, error) {
	var c Config
	dec := &mapstructure.DecoderConfig{
		DecodeHook:       decoderHook(),
		WeaklyTypedInput: true, /* tolerate "123" → int, single string → []string */
		TagName:          "mapstructure",
		Result:           &c,
	}

	decoder, err := mapstructure.NewDecoder(dec)
	if err != nil {
		return c, err
	}

	if err := decoder.Decode(v.AllSettings()); err != nil {
		return c, err
	}

	return c, nil
}
