package skid

import "testing"

func TestFromPublicKey(t *testing.T) {
	for _, td := range allTestdata {
		t.Run(td.name, td.testFromPublicKey)
	}
}

func (td testdata) testFromPublicKey(t *testing.T) {
	want := SKID(td.Bytes)

	if got, err := FromPublicKey(td.pubkey); err != nil || !got.Equal(want) {
		t.Errorf("FromPublicKey(...) == (%s, %v); wanted (%s, %v)", got, err, want, nil)
	}
}
