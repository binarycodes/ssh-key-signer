package cli

import (
	"binarycodes/ssh-keysign/internal/constants"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func WireCommonFlags(c *cobra.Command) {
	c.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Config precedence: flags > env > file > defaults.
		configFilePath, _ := cmd.Flags().GetString("config")
		if configFilePath != "" {
			viper.SetConfigFile(configFilePath)
			viper.SetConfigType("yaml")
		} else {
			switch cmd.Name() {
			case "user":
				if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
					viper.SetConfigFile(filepath.Join(runtimeDir, constants.AppName, constants.ConfigFileName))
				} else if home, err := os.UserHomeDir(); err == nil && home != "" {
					viper.SetConfigFile(filepath.Join(home, ".config", constants.AppName, constants.ConfigFileName))
				}
			case "host":
				configPath := filepath.Join("/etc", constants.AppName, constants.ConfigFileName)
				viper.SetConfigFile(configPath)
			}
			viper.SetConfigType("yaml")
		}

		viper.SetEnvPrefix(strings.ToUpper(constants.AppName))
		viper.AutomaticEnv()

		// Missing config file is OK.
		_ = viper.ReadInConfig()

		return nil
	}

	// global/persistent (available to all subcommands)
	c.PersistentFlags().StringP("config", "c", "", "path to config file")
	c.PersistentFlags().Uint64P("duration", "d", 0, "duration in seconds")

	c.PersistentFlags().String("ca-server-url", "", "CA server URL")
	c.PersistentFlags().String("client-id", "", "OIDC client ID")
	c.PersistentFlags().String("client-secret", "", "OIDC client secret")
	c.PersistentFlags().String("token-url", "", "OIDC token URL")

	// Bind once; values resolved at read time.
	_ = viper.BindPFlag("duration", c.PersistentFlags().Lookup("duration"))
	_ = viper.BindPFlag("ca_server_url", c.PersistentFlags().Lookup("ca-server-url"))
	_ = viper.BindPFlag("client_id", c.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("client_secret", c.PersistentFlags().Lookup("client-secret"))
	_ = viper.BindPFlag("token_url", c.PersistentFlags().Lookup("token-url"))

}
