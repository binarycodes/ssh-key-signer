package cmd_test

import (
	"binarycodes/ssh-keysign/cmd"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestUniqueShortFlags(t *testing.T) {
	root := cmd.BuildRootCmd()
	if root == nil {
		t.Fatal("BuildRootCmd returned nil")
	}

	// Walk the command tree and assert each command’s *effective* flags
	// (inherited + local) don’t reuse the same shorthand for different names.
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		t.Run(c.CommandPath(), func(t *testing.T) {
			seen := map[string]string{} // short -> long name

			check := func(f *pflag.Flag) {
				if f.Shorthand == "" {
					return
				}
				// Ignore Cobra’s built-in help (-h)
				if f.Shorthand == "h" && f.Name == "help" {
					return
				}
				if prev, ok := seen[f.Shorthand]; ok && prev != f.Name {
					t.Fatalf("short -%s reused by %q and %q on command %q",
						f.Shorthand, prev, f.Name, c.CommandPath())
				}
				seen[f.Shorthand] = f.Name
			}

			// Inherited persistent flags + local flags both visible on the command
			c.InheritedFlags().VisitAll(check)
			c.Flags().VisitAll(check)
		})

		for _, sc := range c.Commands() {
			walk(sc)
		}
	}
	walk(root)
}
