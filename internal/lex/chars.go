package lex

func SetOf(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func IsUpperASCII(c byte) bool { return c >= 'A' && c <= 'Z' }

func IsLowerASCII(c byte) bool { return c >= 'a' && c <= 'z' }

func IsDigitASCII(c byte) bool { return c >= '0' && c <= '9' }

func IsAlnumASCII(c byte) bool { return IsUpperASCII(c) || IsLowerASCII(c) || IsDigitASCII(c) }

func RuneLen(s string) int { return len([]rune(s)) }
