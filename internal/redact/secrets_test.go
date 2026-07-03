package redact

// xs decodes a secret-bearing test vector stored with the "xb64" transform:
// base64-decode, then cyclic-XOR with corpusXORKey (defined in
// corpus_test.go). It is the inline-literal counterpart to
// decodeCorpusField, used so that no literal, format-valid synthetic
// credential (fake AWS/Stripe/Slack/GitHub/Discord/SendGrid/HuggingFace/
// OpenAI/Anthropic/GCP/JWT/PEM/Google-OAuth key) ever lands in this repo's
// git history, where platform secret-scanning push-protection would rightly
// block it. A scanner that base64-decodes an "xb64" value sees only XOR
// noise. The transform is deterministic (fixed key, no RNG) and is not a
// security boundary — its sole job is keeping credential shapes out of git.
//
// It panics on a decode error so it can be used directly in package-level
// table literals; a bad encoding fails the test loudly rather than silently
// substituting wrong data.
func xs(enc string) string {
	s, err := decodeCorpusField(enc)
	if err != nil {
		panic("redact test: bad xb64 secret encoding " + enc + ": " + err.Error())
	}
	return s
}
