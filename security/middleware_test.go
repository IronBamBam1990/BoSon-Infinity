package security

import "testing"

func TestRateLimiterV2(t *testing.T) {
	rl := NewRateLimiterV2()

	for i := 0; i < 5; i++ {
		if !rl.Allow("192.168.1.1", 5) {
			t.Errorf("should allow request %d", i+1)
		}
	}

	if rl.Allow("192.168.1.1", 5) {
		t.Error("should reject after limit exceeded")
	}

	if !rl.Allow("10.0.0.1", 5) {
		t.Error("different IP should be allowed")
	}
}
