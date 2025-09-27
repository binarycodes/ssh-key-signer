package cmd

import (
	"binarycodes/ssh-keysign/internal/app"
	"binarycodes/ssh-keysign/internal/constants"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   constants.AppName,
	Short: "ssh key certificate generator - get ssh keys signed by the configured CA server",
	Args:  cobra.NoArgs,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Config precedence: flags > env > file > defaults.
		cfgFile, _ := cmd.Flags().GetString("config")
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
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
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {

		if kind := app.KindOf(err); kind != app.KUnknown {

			if helpMethod := app.HelpFor(err); helpMethod != nil {
				helpMethod()
				fmt.Fprintln(os.Stderr)
			}

			fmt.Fprintln(os.Stderr, err)
			os.Exit(kind.ExitCode())
		} else {
			fmt.Fprintln(os.Stderr, err)
		}

		os.Exit(1)
	}
}

func init() {
	// global/persistent (available to all subcommands)
	rootCmd.PersistentFlags().String("config", "", "path to config file (default: /etc/app.conf)")
	rootCmd.PersistentFlags().Uint64("duration", 0, "duration in seconds (optional)")

	rootCmd.PersistentFlags().String("ca-server-url", "", "CA server URL (required for host)")
	rootCmd.PersistentFlags().String("client-id", "", "OIDC client ID (required for host)")
	rootCmd.PersistentFlags().String("client-secret", "", "OIDC client secret (required for host)")
	rootCmd.PersistentFlags().String("token-url", "", "OIDC token URL (required for host)")

	// Bind once; values resolved at read time.
	_ = viper.BindPFlag("duration", rootCmd.PersistentFlags().Lookup("duration"))
	_ = viper.BindPFlag("ca_server_url", rootCmd.PersistentFlags().Lookup("ca-server-url"))
	_ = viper.BindPFlag("client_id", rootCmd.PersistentFlags().Lookup("client-id"))
	_ = viper.BindPFlag("client_secret", rootCmd.PersistentFlags().Lookup("client-secret"))
	_ = viper.BindPFlag("token_url", rootCmd.PersistentFlags().Lookup("token-url"))

	// sane default examples (optional)
	viper.SetDefault("duration", uint64((30 * time.Minute).Seconds()))
}
