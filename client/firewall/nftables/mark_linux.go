//go:build !android

package nftables

import (
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// ctMarkOrExprs returns the nftables expressions to OR a flag bit into the connection mark:
//
//	ct mark set (ct mark & ^flag) ^ flag
//
// The bitwise algebra clears the flag bit unconditionally then XORs it in, which is an
// idempotent set: the bit is always 1 after the operation and all other bits are preserved.
// Using OR semantics means multiple connection-mark rules on the same connection do not
// overwrite each other's flags.
func ctMarkOrExprs(flag uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^flag),
			Xor:            binaryutil.NativeEndian.PutUint32(flag),
		},
		&expr.Ct{Key: expr.CtKeyMARK, Register: 1, SourceRegister: true},
	}
}

// metaMarkOrExprs returns the nftables expressions to OR a flag bit into the packet mark:
//
//	meta mark set (meta mark & ^flag) ^ flag
//
// Same idiom as ctMarkOrExprs, but for the packet mark (expr.MetaKeyMARK) instead of the
// connection mark. Several of our packet-mark rules can apply to the same packet (e.g. a
// route NAT masquerade mark together with a redirect mark), and OR semantics let them
// coexist instead of one write clobbering another.
func metaMarkOrExprs(flag uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^flag),
			Xor:            binaryutil.NativeEndian.PutUint32(flag),
		},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	}
}

// metaMarkHasExprs returns the nftables expressions to test whether a flag bit is set in the
// packet mark:
//
//	(meta mark & flag) == flag
//
// This is a masked equality check — it passes only when all bits of flag are set in the
// packet mark, regardless of what other bits are present. Using a masked check means the
// rule still matches even when other flags are OR-combined into the same packet mark.
func metaMarkHasExprs(flag uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(flag),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(flag),
		},
	}
}
