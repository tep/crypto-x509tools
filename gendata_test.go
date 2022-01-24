package x509tools

// NOTE: These are use to generate the values in data_test.go

/*
func TestDummy(t *testing.T) {
	for ku := x509.KeyUsage(1); ku < 512; ku++ {
		ext, err := KeyUsageExtension(ku)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%3d: []byte{%s},\n", ku, hexVals(ext.Value))
	}
}

func hexVals(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	list := make([]string, len(b))
	for i, v := range b {
		list[i] = fmt.Sprintf("0x%02X", v)
	}
	return fmt.Sprintf("%s", strings.Join(list, ", "))
}
*/
