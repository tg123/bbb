package acr

import "testing"

func TestValidateLocalNames(t *testing.T) {
	for _, names := range [][]string{
		{"A", "a"},
		{"\u00e9", "e\u0301"},
		{"file", "file/child"},
		{"file/child", "FILE"},
		{"a", "a"},
		{"a//file"},
		{"a/./file"},
		{"../file"},
		{"NUL"},
		{"file."},
		{"file::$DATA"},
	} {
		if err := ValidateLocalNames(names); err == nil {
			t.Errorf("accepted conflicting or invalid names: %q", names)
		}
	}
	if err := ValidateLocalNames([]string{"dir/file", "dir/other", "Elsewhere"}); err != nil {
		t.Fatalf("rejected distinct names: %v", err)
	}
}
