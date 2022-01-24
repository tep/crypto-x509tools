// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509tools provides various x509 related helper functions that are
// not found in the standard library.
//
package x509tools // import "toolman.org/crypto/x509tools"

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// NOTE: Most of the logic in this files is pulled (almost) verbatim
//       from the standard library's crypto/x509 package.

var keyUsageOID []int = asn1.ObjectIdentifier([]int{2, 5, 29, 15})

// KeyUsageExtension converts the provided x509.KeyUsage bitmask to
// a pkix.Extension representing those values. Note that the returned
// Extension alaways has its Critical flag set.
//
// If a non-nil error is returned, it will come from an asn1 marshaling
// falure and the Extension value should be ignored.
func KeyUsageExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	ext := pkix.Extension{Id: keyUsageOID, Critical: true}
	var a [2]byte
	a[0] = reverseBitsInAByte(byte(usage))
	a[1] = reverseBitsInAByte(byte(usage >> 8))

	l := 1
	if a[1] != 0 {
		l = 2
	}

	bs := a[:l]

	var err error
	if ext.Value, err = asn1.Marshal(asn1.BitString{Bytes: bs, BitLength: asn1BitLength(bs)}); err != nil {
		return ext, err
	}
	return ext, nil
}

func reverseBitsInAByte(in byte) byte {
	b1 := in>>4 | in<<4
	b2 := b1>>2&0x33 | b1<<2&0xcc
	b3 := b2>>1&0x55 | b2<<1&0xaa
	return b3
}

// asn1BitLength returns the bit-length of bitString by considering the
// most-significant bit in a byte to be the "first" bit. This convention
// matches ASN.1, but differs from almost everything else.
func asn1BitLength(bitString []byte) int {
	bitLen := len(bitString) * 8

	for i := range bitString {
		b := bitString[len(bitString)-i-1]

		for bit := uint(0); bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				return bitLen
			}
			bitLen--
		}
	}

	return 0
}
