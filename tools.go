//go:build tools
// +build tools

package main

import (
	_ "github.com/vektra/mockery/v2"
	_ "golang.org/x/tools/cmd/stringer"
)
