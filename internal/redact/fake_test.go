package redact

import "testing"

func TestLooksFake(t *testing.T) {
	for v, fake := range map[string]bool{
		"abcdefghijklmnop1234":                            true,
		"sk-ant-api03-ZmFrZUtleUZvclRlc3RzT25see12345678": true, // base64 of "fakeKeyForTestsOn…"
		"AKIAIOSFODNN7EXAMPLE":                            true,
		"ghp_" + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx":   true,
		"hunter2pass":                                     true,
		"sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc":           true,
		"ghp_" + "R7kQ2mXv9LpZ4tW8nB3cYj6HdF1sG5aE0uKo":   false,
		"AKIA" + "Q3VRX7ZK2NPLM5TB":                       false,
		"xoxb-" + "2958473610-Hq8VnLz3KdWp7Rf":            false,
	} {
		if got := LooksFake(v); got != fake {
			t.Errorf("LooksFake(%q) = %v, want %v", v, got, fake)
		}
	}
}
