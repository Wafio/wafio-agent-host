package ebpf

import (
	"strings"
	"unicode/utf8"
)

// ────────────────────────────────────────────────────────────────────────────
//  Process-name matching modes
//
//  A MatchComm term used to be a case-insensitive substring, so a kill policy
//  for "nc" also killed runc and rsync. New policies compare whole words; the
//  substring mode stays available, and policies written before the field keep
//  it, because silently narrowing them would stop alerts their owners rely on.
// ────────────────────────────────────────────────────────────────────────────

// effectiveCommMatchMode is the mode matchPolicy applies. An empty mode can
// only reach matching from a caller that bypassed the engine's normalization
// (tests, older snapshots); it keeps the legacy substring semantics.
func effectiveCommMatchMode(mode string) string {
	if mode == "" {
		return CommMatchSubstring
	}
	return mode
}

// commTermMatches compares one lower-cased term with a lower-cased process
// name under mode.
func commTermMatches(mode, term, name string) bool {
	switch mode {
	case CommMatchExact:
		// comm is truncated to TASK_COMM_LEN-1 bytes by the kernel; a longer
		// term still names the process.
		return name == term || (len(term) > taskCommLen-1 && name == truncateComm(term))
	case CommMatchWord:
		return containsWord(name, term)
	default:
		return strings.Contains(name, term)
	}
}

// containsWord reports whether term occurs in s with a non-letter (or the
// edge of s) on both sides. Digits, dots and dashes delimit, so version
// suffixes (python3, php-fpm8.2) still match their family name.
func containsWord(s, term string) bool {
	if term == "" {
		return false
	}
	for from := 0; from+len(term) <= len(s); {
		i := strings.Index(s[from:], term)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(term)
		if !letterBefore(s, start) && !letterAt(s, end) {
			return true
		}
		_, size := utf8.DecodeRuneInString(s[start:])
		from = start + size
	}
	return false
}

func letterBefore(s string, i int) bool {
	if i == 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return isLetter(r)
}

func letterAt(s string, i int) bool {
	if i >= len(s) {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s[i:])
	return isLetter(r)
}

func isLetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// ── Narrowing strength ──────────────────────────────────────────────────────
