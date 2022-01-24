package x509tools

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"reflect"
	"testing"
)

func TestKeyUsageExtension(t *testing.T) {
	var tests []*testcase
	for i, v := range testExtensionValues {
		if v == nil {
			continue
		}
		tests = append(tests, mkTestcase(x509.KeyUsage(i), v))
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("#%03d", i+1), tc.test)
	}
}

type testcase struct {
	usage x509.KeyUsage
	want  pkix.Extension
}

func (tc *testcase) test(t *testing.T) {
	if got, err := KeyUsageExtension(tc.usage); err != nil || !reflect.DeepEqual(got, tc.want) {
		t.Errorf("KeyUsageExtension(%s) == (%v, %v); wanted (%v, %v)", KeyUsageString(tc.usage), got, err, tc.want, nil)
	}
}

func mkTestcase(ku x509.KeyUsage, values []byte) *testcase {
	return &testcase{
		usage: ku,
		want: pkix.Extension{
			Id:       keyUsageOID,
			Value:    values,
			Critical: true,
		},
	}
}
