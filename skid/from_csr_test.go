package skid

import "testing"

func TestFromCSR(t *testing.T) {
	for _, td := range allTestdata {
		t.Run(td.name, td.testFromCSR)
	}
}

func (td testdata) testFromCSR(t *testing.T) {
	want := SKID(td.Bytes)

	if got, err := FromCSR(td.req); err != nil || !got.Equal(want) {
		t.Errorf("FromCSR(...) == (%q, %v); wanted (%q, %v)", got, err, want, nil)
	}
}
