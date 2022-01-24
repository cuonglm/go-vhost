//go:build amd64 && !noasm
// +build amd64,!noasm

package p384

import "github.com/Windscribe/go-vhost/internal/cpu"

var hasBMI2 = cpu.X86.HasBMI2 //nolint
