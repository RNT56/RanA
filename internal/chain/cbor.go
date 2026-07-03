package chain

import "github.com/fxamacker/cbor/v2"

// canonEncMode and canonDecMode are chain's shared canonical CBOR encode
// and strict decode modes (RFC 8949 Core Deterministic Encoding), used by
// both seg-header hashing and checkpoint signing so both go through
// identical, bytewise-sorted, definite-length encoding — the determinism
// docs/TRUST.md §1 requires.
var (
	canonEncMode cbor.EncMode
	canonDecMode cbor.DecMode
)

func init() {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("chain: failed to build canonical encode mode: " + err.Error())
	}
	canonEncMode = em

	dopts := cbor.DecOptions{
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
	}
	dm, err := dopts.DecMode()
	if err != nil {
		panic("chain: failed to build strict decode mode: " + err.Error())
	}
	canonDecMode = dm
}
