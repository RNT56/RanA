package profile

// builtinSensitivePaths is the D9 in-kernel sensitive-read watchlist base
// (RANA-plan-v1.md D9): credential directories whose read is the highest-
// signal event class RanA records. Profiles may only ADD to this list
// ([sensitive_read].extra); nothing here is ever removable by a profile.
var builtinSensitivePaths = []string{
	"~/.ssh",
	"~/.aws",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gcloud",
	// browser profile dirs (credential/cookie stores)
	"~/.config/google-chrome",
	"~/.config/chromium",
	"~/.mozilla/firefox",
	"~/Library/Application Support/Google/Chrome",
	"~/Library/Application Support/Firefox",
	// D9 explicitly calls out this one as a named built-in example.
	"~/.openclaw/credentials*",
}

// BuiltinSensitivePaths returns the built-in sensitive-read watchlist (D9),
// plus, when datadir is non-empty, RanA's own data directory (ledger,
// signing key, salt) per plan D27: "RanA's own data directory ... is on the
// built-in sensitive-read/write watchlist, so a recorded agent touching the
// recorder is itself a first-class, alertable event." The returned slice is
// a fresh copy each call — callers may append to it freely.
func BuiltinSensitivePaths(datadir string) []string {
	out := make([]string, 0, len(builtinSensitivePaths)+1)
	out = append(out, builtinSensitivePaths...)
	if datadir != "" {
		out = append(out, datadir)
	}
	return out
}
