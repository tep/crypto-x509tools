package skid

import "testing"

func TestString(t *testing.T) {
	for _, td := range allTestdata {
		t.Run(td.name, td.testString)
	}
}

func (td testdata) testString(t *testing.T) {
	skid := SKID(td.Bytes)
	want := td.Text

	if got := skid.String(); got != want {
		t.Errorf("skid.String() == %q; wanted %q", got, want)
	}
}
