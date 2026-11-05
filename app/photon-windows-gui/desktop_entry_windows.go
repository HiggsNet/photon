//go:build windows

package main

func defaultCommandArgs(args []string) []string {
	if len(args) == 0 {
		return []string{"gui"}
	}
	return args
}
