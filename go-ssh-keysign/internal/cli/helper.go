package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
)

func WireCommonFlags(c *cobra.Command) {
	c.Flags().StringP("config", "c", "", "path to config file")
	c.Flags().String("ca-server-url", "", "CA server URL")
	c.Flags().String("client-id", "", "OIDC client ID")
	c.Flags().String("client-secret", "", "OIDC client secret")
	c.Flags().String("token-url", "", "OIDC token URL")

	prevPreRunE := c.PreRunE
	c.PreRunE = func(cmd *cobra.Command, args []string) error {
		v := viper.New()

		if err := errors.Join(
			v.BindPFlags(cmd.Flags()),
			v.BindPFlags(cmd.InheritedFlags()),
		); err != nil {
			return err
		}

		cmd.SetContext(ctxkeys.WithViper(cmd.Context(), v))

		if err := ReadConfigFile(cmd, v); err != nil {
			return err
		}

		v.SetEnvPrefix(strings.ToUpper(constants.AppName))
		v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
		v.AutomaticEnv()

		if prevPreRunE != nil {
			if err := prevPreRunE(cmd, args); err != nil {
				return err
			}
		}

		return nil
	}
}

func ReadConfigFile(cmd *cobra.Command, v *viper.Viper) error {
	if f := cmd.Flags().Lookup("config"); f == nil {
		return nil
	}

	configFilePath, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}

	if configFilePath != "" {
		v.SetConfigFile(configFilePath)
		v.SetConfigType("yaml")

		if err := v.ReadInConfig(); err != nil {
			return apperror.ErrFileSystem(fmt.Errorf("failed to read config %q: %w", configFilePath, err))
		}
	} else {
		switch cmd.Name() {
		case "user":
			if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
				v.SetConfigFile(filepath.Join(runtimeDir, constants.AppName, constants.ConfigFileName))
			} else if home, err := os.UserHomeDir(); err == nil && home != "" {
				v.SetConfigFile(filepath.Join(home, ".config", constants.AppName, constants.ConfigFileName))
			}
		case "host":
			configPath := filepath.Join(constants.EtcDir, constants.AppName, constants.ConfigFileName)
			v.SetConfigFile(configPath)
		}
		v.SetConfigType("yaml")

		if err := v.ReadInConfig(); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return apperror.ErrFileSystem(fmt.Errorf("failed to read default config: %w", err))
			}
		}
	}

	return nil
}
