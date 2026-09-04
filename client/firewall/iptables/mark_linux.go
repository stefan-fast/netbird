//go:build !android

package iptables

import "fmt"

// fwmarkMask formats a fwmark value as "value/value" for use with iptables
// MARK/CONNMARK --set-mark/--set-xmark and -m mark/-m connmark --mark. Using
// the same value as both value and mask is the iptables idiom for OR-set
// (when setting) or masked bit-test (when matching): only the bits defined by
// the mark constant are affected or tested, leaving all other bits intact.
// This lets several of our marks coexist on the same packet or connection
// instead of one write clobbering another.
func fwmarkMask(mark uint32) string {
	return fmt.Sprintf("%#x/%#x", mark, mark)
}
