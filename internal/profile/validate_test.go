package profile

import (
	"errors"
	"testing"
)

func mustHeader() string {
	return "[profile]\nname = \"t\"\ndescription = \"d\"\nversion = 1\n"
}

func TestValidate_MissingProfileSection(t *testing.T) {
	_, err := Parse("[match]\nauto = true\n", "test")
	if !errors.Is(err, ErrMissingProfileSection) {
		t.Fatalf("err = %v, want ErrMissingProfileSection", err)
	}
}

func TestValidate_MissingName(t *testing.T) {
	_, err := Parse("[profile]\ndescription = \"d\"\nversion = 1\n", "test")
	if !errors.Is(err, ErrMissingName) {
		t.Fatalf("err = %v, want ErrMissingName", err)
	}
}

func TestValidate_CaptureExecFalseRejected(t *testing.T) {
	src := mustHeader() + "\n[capture]\nexec = false\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrCaptureDisabled) {
		t.Fatalf("err = %v, want ErrCaptureDisabled", err)
	}
}

func TestValidate_CaptureNetworkConnectFalseRejected(t *testing.T) {
	src := mustHeader() + "\n[capture]\nnetwork_connect = false\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrCaptureDisabled) {
		t.Fatalf("err = %v, want ErrCaptureDisabled", err)
	}
}

func TestValidate_CaptureOtherClassesMayBeDisabled(t *testing.T) {
	// v1 baseline keeps everything on, but only exec/network_connect are
	// hard-frozen; other classes narrowing is a "future policy" hook per
	// docs/PROFILES.md, not itself invalid. This test documents the
	// boundary: fork_exit=false alone must NOT trigger ErrCaptureDisabled.
	src := mustHeader() + "\n[capture]\nfork_exit = false\n"
	_, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_LooserEntropyMinLenRejected(t *testing.T) {
	// default minLen is 20; a larger minLen is looser (catches fewer tokens).
	src := mustHeader() + "\n[redaction]\nentropy_min_len = 30\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrLooserEntropy) {
		t.Fatalf("err = %v, want ErrLooserEntropy", err)
	}
}

func TestValidate_LooserEntropyThresholdRejected(t *testing.T) {
	// default bitsPerChar is 4.0; a lower value is looser.
	src := mustHeader() + "\n[redaction]\nentropy_threshold = 2.0\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrLooserEntropy) {
		t.Fatalf("err = %v, want ErrLooserEntropy", err)
	}
}

func TestValidate_StricterEntropyAccepted(t *testing.T) {
	src := mustHeader() + "\n[redaction]\nentropy_min_len = 10\nentropy_threshold = 4.5\n"
	_, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_UnsetEntropyFieldsAccepted(t *testing.T) {
	src := mustHeader() + "\n[redaction]\nextra_patterns = [\"foo\"]\n"
	_, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_InvalidExtraPatternRejected(t *testing.T) {
	src := mustHeader() + "\n[redaction]\nextra_patterns = [\"(unclosed\"]\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrInvalidPattern) {
		t.Fatalf("err = %v, want ErrInvalidPattern", err)
	}
}

func TestValidate_InvalidGlobRejected(t *testing.T) {
	src := mustHeader() + "\n[digest]\nscopes = [\"[unclosed\"]\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrInvalidGlob) {
		t.Fatalf("err = %v, want ErrInvalidGlob", err)
	}
}

func TestValidate_InvalidTimelineLensRejected(t *testing.T) {
	src := mustHeader() + "\n[timeline]\nlens = \"bogus\"\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrInvalidTimelineLens) {
		t.Fatalf("err = %v, want ErrInvalidTimelineLens", err)
	}
}

func TestValidate_NegativeRetentionRejected(t *testing.T) {
	src := mustHeader() + "\n[retention]\nttl_days = -1\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrInvalidRetention) {
		t.Fatalf("err = %v, want ErrInvalidRetention", err)
	}
}

func TestValidate_MarkerForbiddenFieldInCarryRejected(t *testing.T) {
	// P7: message/prompt/completion text must never be carriable, even if a
	// profile author tries to allowlist it under carry_fields.
	src := mustHeader() + "\n[markers]\nenabled = true\ncarry_fields = [\"runId\", \"prompt\"]\n"
	_, err := Parse(src, "test")
	if !errors.Is(err, ErrMarkerForbiddenField) {
		t.Fatalf("err = %v, want ErrMarkerForbiddenField", err)
	}
}

func TestValidate_MarkerAllForbiddenFieldsCaught(t *testing.T) {
	for _, f := range forbiddenMarkerFields {
		src := mustHeader() + "\n[markers]\nenabled = true\ncarry_fields = [\"" + f + "\"]\n"
		_, err := Parse(src, "test")
		if !errors.Is(err, ErrMarkerForbiddenField) {
			t.Fatalf("field %q: err = %v, want ErrMarkerForbiddenField", f, err)
		}
	}
}

func TestValidate_ValidMarkerFieldsAccepted(t *testing.T) {
	src := mustHeader() + "\n[markers]\nenabled = true\ncarry_fields = [\"runId\", \"agentId\", \"channel\", \"status\"]\n"
	_, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
