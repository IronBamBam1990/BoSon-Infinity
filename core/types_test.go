package core

import "testing"

func TestInitConsensus(t *testing.T) {
	InitConsensus()

	if UNIT != 100_000_000 {
		t.Errorf("UNIT should be 100000000, got %d", UNIT)
	}
	if REWARD0_UNITS != 50*100_000_000 {
		t.Errorf("REWARD0_UNITS should be 5000000000, got %d", REWARD0_UNITS)
	}
	if MAX_SUPPLY_UNITS != 50_000_000*100_000_000 {
		t.Errorf("MAX_SUPPLY_UNITS wrong, got %d", MAX_SUPPLY_UNITS)
	}
}

func TestIsValidAddr(t *testing.T) {
	tests := []struct {
		addr  string
		valid bool
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"", false},
		{"too_short", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}

	for _, tt := range tests {
		got := IsValidAddr(tt.addr)
		if got != tt.valid {
			t.Errorf("IsValidAddr(%q) = %v, want %v", tt.addr, got, tt.valid)
		}
	}
}

func TestValidatePeerAddr(t *testing.T) {
	tests := []struct {
		addr  string
		valid bool
	}{
		{"http://1.2.3.4:8081", true},
		{"https://node.example.com:443", true},
		{"http://203.0.113.1:8081", true},
		{"http://127.0.0.1:8081", false},
		{"http://localhost:8081", false},
		{"http://10.0.0.1:8081", false},
		{"http://192.168.1.1:8081", false},
		{"http://172.16.0.1:8081", false},
		{"http://169.254.169.254/latest", false},
		{"ftp://1.2.3.4", false},
		{"", false},
		{"just-a-string", false},
	}

	for _, tt := range tests {
		got := ValidatePeerAddr(tt.addr)
		if got != tt.valid {
			t.Errorf("ValidatePeerAddr(%q) = %v, want %v", tt.addr, got, tt.valid)
		}
	}
}

func TestShort(t *testing.T) {
	if Short("abcdefghij") != "abcdefgh" {
		t.Error("Short should truncate to 8 chars")
	}
	if Short("abc") != "abc" {
		t.Error("Short should not truncate short strings")
	}
}

func TestCopyState(t *testing.T) {
	orig := map[string]Account{
		"a": {Balance: 100, Nonce: 1},
	}
	cp := CopyState(orig)
	cp["a"] = Account{Balance: 200, Nonce: 2}

	if orig["a"].Balance != 100 {
		t.Error("CopyState should not modify original")
	}
}
