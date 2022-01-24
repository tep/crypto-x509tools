package x509tools

import (
	"fmt"
	"strconv"
	"testing"
)

type testByte byte

func TestReverseBitsInAByte(t *testing.T) {
	for i := testByte(0); i < 0xFF; i++ {
		t.Run(fmt.Sprintf("0x%04X", i), i.test)
	}
}

func (tb testByte) test(t *testing.T) {
	s := fmt.Sprintf("%08b", tb)
	r := reverse(s)

	want, err := parseBinaryByte(r)
	if err != nil {
		t.Fatal(err)
	}

	if got := reverseBitsInAByte(byte(tb)); got != want {
		t.Errorf("mirrorBits(0x%02X) == 0x%02X; wanted: 0x%02X", tb, got, want)
	}
}

func reverse(s string) string {
	r := []byte(s)
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

func parseBinaryByte(s string) (byte, error) {
	v, err := strconv.ParseUint(s, 2, 8)
	if err != nil {
		return 0, err
	}
	return byte(v), nil
}
