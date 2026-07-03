package chainmutations

import "testing"

import "github.com/RNT56/RanA/internal/ledger"

// TestCleanLedgerVerifiesOK proves the fixture itself is a legitimate,
// fully-verifiable ledger before any mutation test suite member touches
// it — a mutation test that "detects tampering" against a fixture that
// was already broken would prove nothing.
func TestCleanLedgerVerifiesOK(t *testing.T) {
	d, _ := buildLedger(t)

	res, err := ledger.Verify(d, ledger.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != ledger.CodeOK {
		t.Fatalf("Code = %d, want CodeOK(0); findings: %+v", res.Code, res.Findings)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected zero findings on a clean ledger, got %+v", res.Findings)
	}
}
