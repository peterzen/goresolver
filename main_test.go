package goresolver

import (
	"os"
	"testing"
	"time"
)

// TestMain sets a fixed current time so that DNSSEC signatures in
// archived fixture data remain valid during the tests.
func TestMain(m *testing.M) {
	nowFunc = func() time.Time {
		// 15 March 2019 00:00:00 UTC is within the validity period of
		// all RRSIG records used in the fixture data.
		return time.Date(2019, 3, 15, 0, 0, 0, 0, time.UTC)
	}
	code := m.Run()
	nowFunc = time.Now
	os.Exit(code)
}
