package main

import "strings"

// splitLines splits s into lines, dropping a single trailing empty line so a
// text block ending in "\n" doesn't produce a spurious blank last element.
func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
