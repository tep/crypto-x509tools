package skid

import "testing"

func TestFromString(t *testing.T) {
	for _, td := range allTestdata {
		t.Run(td.name, td.testFromString)
	}
}

func (td testdata) testFromString(t *testing.T) {
	want := SKID(td.Bytes)
	if got, err := FromString(td.Text); err != nil || !got.Equal(want) {
		t.Errorf("FromString(%q) == (%v, %v); wanted (%v, %v)", td.Text, got, err, want, nil)
	}
}
