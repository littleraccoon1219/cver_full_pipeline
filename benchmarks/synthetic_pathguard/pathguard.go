package pathguard

import (
    "errors"
    "path/filepath"
    "strings"
)

// ResolveVulnerable is intentionally defective. It is isolated in a synthetic
// fixture and must never be used by production code.
func ResolveVulnerable(root, requested string) (string, error) {
    if root == "" {
        return "", errors.New("empty root")
    }
    return filepath.Join(root, requested), nil
}

// ResolveFixed canonicalizes both paths and verifies the final path is inside root.
func ResolveFixed(root, requested string) (string, error) {
    canonicalRoot, err := filepath.Abs(root)
    if err != nil {
        return "", err
    }
    candidate, err := filepath.Abs(filepath.Join(canonicalRoot, requested))
    if err != nil {
        return "", err
    }
    relative, err := filepath.Rel(canonicalRoot, candidate)
    if err != nil {
        return "", err
    }
    if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
        return "", errors.New("path escapes root")
    }
    return candidate, nil
}
