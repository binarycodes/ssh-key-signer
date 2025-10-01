package main

import (
	"fmt"
	"os"

	"binarycodes/ssh-keysign/cmd"
	"binarycodes/ssh-keysign/internal/ctxkeys"
)

func main() {
	if err := cmd.InitRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cmd.Execute()

	if rc := cmd.BuildRootCmd(); rc != nil {
		if v := ctxkeys.CleanupFrom(rc.Context()); v != nil {
			if err := v(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}
