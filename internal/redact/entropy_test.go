package redact

import "testing"

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		wantMin float64
		wantMax float64
	}{
		{"empty", "", 0, 0},
		{"single-char-repeated", "aaaaaaaaaa", 0, 0.01},
		{"low-entropy-word", "password", 0, 3.0},
		{"high-entropy-random", "aB3xQ9zR7mK2pL8vN4wT", 3.8, 4.5},
		{"hex-blob", "5f3759df8b1acffe6e6a1e2b3c4d5e6f", 3.5, 4.1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shannonEntropy(tt.s)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("shannonEntropy(%q) = %v, want in [%v,%v]", tt.s, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestIsDictionaryWord(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"password", true},
		{"the", true},
		{"Configuration", true},
		{"xK9pL2mQ7vN4wR8t", false},
		{"", false},
		{"zzqxvw", false},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := isDictionaryWord(tt.s); got != tt.want {
				t.Errorf("isDictionaryWord(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestLooksHighEntropyBlob(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"5f3759df8b1acffe6e6a1e2b3c4d5e6f", true},     // 32 hex chars
		{"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=", true}, // base64, >=24, high H
		{"short", false},
		{"0123456789abcdef0123456789abcdef", true}, // 32 hex
		// Recalibration: pure-hex is caught at >= 16 chars (fixed 4 bits/char),
		// the class of sub-32 secret that used to leak.
		{"7dcef58168aa53f9d9a06afe", true}, // 24 hex
		{"a1b2c3d4e5f60718", true},         // 16 hex
		{"a1b2c3d4e5f607", false},          // 14 hex, below the hex floor
		// Base64 needs the longer floor AND the Shannon bar, so a short
		// structured identifier is NOT redacted on shape alone.
		{"getUserByName123", false},         // 16-char identifier, below base64 floor
		{"aaaaaaaaaaaaaaaaaaaaaaaa", false}, // 24 chars but ~0 entropy
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := looksHighEntropyBlob(tt.s); got != tt.want {
				t.Errorf("looksHighEntropyBlob(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsHighEntropyToken(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"too-short", "aB3xQ9zR7mK2", false},
		{"long-random", "aB3xQ9zR7mK2pL8vN4wT6yU1", true},
		{"long-dictionary-repeat", "thethethethethethethethethe", false},
		{"long-low-entropy", "aaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isHighEntropyToken(tt.s, 20, 4.0); got != tt.want {
				t.Errorf("isHighEntropyToken(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
