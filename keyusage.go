package x509tools

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

// KeyUsage is a convenience wrapper around x509.KeyUsage that provides the
// String and Extension methods.
type KeyUsage x509.KeyUsage

// String implements the fmt.Stringer interface for type KeyUsage.
func (ku KeyUsage) String() string {
	return KeyUsageString(x509.KeyUsage(ku))
}

// Extension is a wrapper around this package's KeyUsageExtension function.
func (ku KeyUsage) Extension() (pkix.Extension, error) {
	return KeyUsageExtension(x509.KeyUsage(ku))
}
