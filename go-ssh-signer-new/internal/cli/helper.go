package cli

import (
	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func WireCommonFlags(c *cobra.Command) {

	c.Flags().StringP("config", "c", "", "path to config file")
	c.Flags().Uint64P("duration", "d", 0, "duration in seconds")
	c.Flags().String("ca-server-url", "", "CA server URL")
	c.Flags().String("client-id", "", "OIDC client ID")
	c.Flags().String("client-secret", "", "OIDC client secret")
	c.Flags().String("token-url", "", "OIDC token URL")

	prevPreRunE := c.PreRunE
	c.PreRunE = func(cmd *cobra.Command, args []string) error {

		v := viper.New()
		_ = v.BindPFlags(cmd.Flags())
		_ = v.BindPFlags(cmd.InheritedFlags())
		cmd.SetContext(ctxkeys.WithViper(cmd.Context(), v))

		configFilePath, _ := cmd.Flags().GetString("config")
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
				configPath := filepath.Join("/etc", constants.AppName, constants.ConfigFileName)
				v.SetConfigFile(configPath)
			}
			v.SetConfigType("yaml")

			if err := v.ReadInConfig(); err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					return apperror.ErrFileSystem(fmt.Errorf("failed to read default config: %w", err))
				}
			}
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
