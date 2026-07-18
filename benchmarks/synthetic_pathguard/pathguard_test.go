package pathguard

import (
    "path/filepath"
    "testing"
)

func TestSyntheticDefectAndFix(t *testing.T) {
    root := filepath.Join(t.TempDir(), "sandbox")
    requested := filepath.Join("..", "sentinel")

    vulnerable, err := ResolveVulnerable(root, requested)
    if err != nil {
        t.Fatalf("vulnerable resolver unexpectedly failed: %v", err)
    }
    relative, err := filepath.Rel(root, vulnerable)
    if err != nil {
        t.Fatal(err)
    }
    if relative != ".." && !(len(relative) > 3 && relative[:3] == ".."+string(filepath.Separator)) {
        t.Fatalf("fixture did not reproduce boundary escape: %q", relative)
    }

    if _, err := ResolveFixed(root, requested); err == nil {
        t.Fatal("fixed resolver accepted an escaping path")
    }
}
