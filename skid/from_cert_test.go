package skid

import (
	"testing"
)

func TestFromCertificate(t *testing.T) {
	for _, td := range allTestdata {
		t.Run(td.name, td.testFromCertificate)
	}
}

func (td testdata) testFromCertificate(t *testing.T) {
	want := SKID(td.Bytes)

	if got, err := FromCertificate(td.cert); err != nil || !got.Equal(want) {
		t.Errorf("FromCertificate(...) == (%q, %v); wanted (%q, %v)", got, err, want, nil)
	}
}
