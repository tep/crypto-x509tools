package x509tools

import (
	"crypto/x509"
	"testing"
)

func TestKeyUsageString(t *testing.T) {
	want := "KeyEncipherment"
	if got := KeyUsageString(x509.KeyUsageKeyEncipherment); got != want {
		t.Errorf("KeyUsageString(x509.KeyUsageKeyEncipherment) == %q; Wanted %q", got, want)
	}
}
