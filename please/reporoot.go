package please

import "strings"

func RepoRoot(plz string) (string, error) {
	out, err := execPlease(plz, "query", "reporoot")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
