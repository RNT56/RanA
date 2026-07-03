package session

import "testing"

func TestIsCgroupPopulated_Populated(t *testing.T) {
	data := []byte("populated 1\nfrozen 0\n")
	got, err := isCgroupPopulated(data)
	if err != nil {
		t.Fatalf("isCgroupPopulated: unexpected error: %v", err)
	}
	if !got {
		t.Errorf("isCgroupPopulated = false, want true")
	}
}

func TestIsCgroupPopulated_Empty(t *testing.T) {
	data := []byte("populated 0\nfrozen 0\n")
	got, err := isCgroupPopulated(data)
	if err != nil {
		t.Fatalf("isCgroupPopulated: unexpected error: %v", err)
	}
	if got {
		t.Errorf("isCgroupPopulated = true, want false")
	}
}

func TestIsCgroupPopulated_FieldOrderIndependent(t *testing.T) {
	data := []byte("frozen 0\npopulated 1\n")
	got, err := isCgroupPopulated(data)
	if err != nil {
		t.Fatalf("isCgroupPopulated: unexpected error: %v", err)
	}
	if !got {
		t.Errorf("isCgroupPopulated = false, want true")
	}
}

func TestIsCgroupPopulated_MissingField(t *testing.T) {
	data := []byte("frozen 0\n")
	if _, err := isCgroupPopulated(data); err == nil {
		t.Fatal("isCgroupPopulated: expected error for missing populated field, got nil")
	}
}

func TestIsCgroupPopulated_EmptyInput(t *testing.T) {
	if _, err := isCgroupPopulated(nil); err == nil {
		t.Fatal("isCgroupPopulated: expected error for empty input, got nil")
	}
}

func TestIsCgroupPopulated_TrailingWhitespaceAndBlankLines(t *testing.T) {
	data := []byte("\npopulated 1  \n\nfrozen 0\n")
	got, err := isCgroupPopulated(data)
	if err != nil {
		t.Fatalf("isCgroupPopulated: unexpected error: %v", err)
	}
	if !got {
		t.Errorf("isCgroupPopulated = false, want true")
	}
}
