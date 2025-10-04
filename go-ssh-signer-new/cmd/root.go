package cmd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"binarycodes/ssh-keysign/internal/apperror"
	"binarycodes/ssh-keysign/internal/cli"
	"binarycodes/ssh-keysign/internal/cli/hostcmd"
	"binarycodes/ssh-keysign/internal/cli/usercmd"
	"binarycodes/ssh-keysign/internal/cli/versioncmd"
	"binarycodes/ssh-keysign/internal/constants"
	"binarycodes/ssh-keysign/internal/ctxkeys"
	"binarycodes/ssh-keysign/internal/logging"
	"binarycodes/ssh-keysign/internal/meta"
)

var rootCmd = &cobra.Command{
	Use:           constants.AppName,
	Short:         "ssh key certificate generator - get ssh keys signed by the configured CA server",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		v := viper.New()
		cmd.SetContext(ctxkeys.WithViper(cmd.Context(), v))

		v.SetEnvPrefix(strings.ToUpper(constants.AppName))
		v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
		v.AutomaticEnv()

		if err := errors.Join(
			v.BindPFlags(cmd.Flags()),
			v.BindPFlags(cmd.PersistentFlags()),
			v.BindPFlags(cmd.InheritedFlags()),
		); err != nil {
			return err
		}

		if err := cli.ReadConfigFile(cmd, v); err != nil {
			return err
		}

		logLevel, lErr := logging.ParseLogLevel(v.GetString("log-level"))
		logDest, dErr := logging.ParseLogDestination(v.GetString("log-dest"))

		if err := errors.Join(lErr, dErr); err != nil {
			return err
		}

		zl, cleanup, err := logging.Build(logging.Logging{
			Level: logLevel, Destination: logDest, Sample: true,
		})
		if err != nil {
			return err
		}

		zl = zl.With(
			zap.String("command", cmd.CommandPath()),
			zap.String("version", meta.Version),
		)

		verbosity, err := cmd.Flags().GetCount("verbose")
		if err != nil {
			return err
		}

		printer := logging.NewPrinter(cmd.OutOrStdout(), verbosity)

		cmd.SetContext(ctxkeys.WithLogger(cmd.Context(), zl))
		cmd.SetContext(ctxkeys.WithLogCleanup(cmd.Context(), cleanup))
		cmd.SetContext(ctxkeys.WithPrinter(cmd.Context(), printer))

		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {

		// Find which command was triggered
		args := os.Args[1:]
		cmd, _, findErr := rootCmd.Find(args)
		if findErr != nil {
			log.Fatal(err)
		}

		kind := apperror.KindOf(err)
		if kind == apperror.KUnknown {
			log.Fatal(err)
		}

		if kind == apperror.KUsage {
			if err := cmd.Help(); err != nil {
				log.Fatal(err)
			}
			_, _ = fmt.Fprintln(rootCmd.ErrOrStderr())
		}

		_, _ = fmt.Fprintln(rootCmd.ErrOrStderr(), err)
		os.Exit(kind.ExitCode())
	}
}

func InitRoot() error {
	rootCmd.AddCommand(versioncmd.NewCommand())
	rootCmd.AddCommand(hostcmd.NewCommand())
	rootCmd.AddCommand(usercmd.NewCommand())

	rootCmd.PersistentFlags().String("log-level", "warn", "info level: error|warn|info|debug")
	rootCmd.PersistentFlags().String("log-dest", "stderr", "log destination: stderr|stdout|file")
	rootCmd.PersistentFlags().CountP("verbose", "v", "Increase user output verbosity (-v, -vv, -vvv)")

	return nil
}

func BuildRootCmd() *cobra.Command {
	// Intended for tests
	return rootCmd
}
