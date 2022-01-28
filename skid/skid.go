// Package skid provides type SKID, along with supporting functions and
// methods. SKID is a byte slice representing an x509 Subject Key Identifier
// as defined by RFC-5280 Section 4.2.1.2.
//
// SKID values constructed by this package are compatible with those generated
// by openssl or the standard library's crtpto/x509 package.
package skid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

var (
	ErrNoCertificate = errors.New("nil cert")
	ErrNoCSR         = errors.New("nil csr")
)

// SKID is a byte slice representing an x509 Subject Key Identifier
// per RFC-5280 Section 4.2.1.2.
type SKID []byte

// Equal returns true if the receiver and the argument are both nil or if all
// of their values agree -- or false if either are nil (but not both), their
// lengths are different, or if any of their values disagree.
func (s SKID) Equal(o SKID) bool {
	switch {
	case s == nil && o == nil:
		return true
	case s == nil || o == nil:
		return false
	case len(s) != len(o):
		return false
	default:
		for i, v := range s {
			if o[i] != v {
				return false
			}
		}
		return true
	}
}

// String returns the colon-separated, hexadecimal representating of the
// receiver -- similar to the following:
//
// 		"67:ED:5B:3B:3B:82:BE:2C:2C:60:E5:ED:5B:39:5F:19:BC:BB:E7:B8"
//
func (s SKID) String() string {
	data := []byte(s)
	list := make([]string, len(data))
	for i, b := range data {
		s := strconv.FormatInt(int64(b), 16)
		switch len(s) {
		case 0:
			list[i] = "00"
		case 1:
			list[i] = "0" + s
		default:
			list[i] = s
		}
	}

	return strings.ToUpper(strings.Join(list, ":"))
}

// FromString returns a SKID value parsed from the given string -- which
// should be a colon-separated, hexadecimal representattion (as generated
// by SKID's String method). If s is the empty string then FromString will
// return a nil SKID and no error.  FromString will return a non-nil error
// if any of its elements fails to parse as a hexadecimal value.
func FromString(s string) (SKID, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ":")
	out := make(SKID, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}

	return out, nil
}

// FromCertificate returns a SKID from the given certificate. If cert is nil
// then FromCertificate returns a nil skid and ErrNoCertificate. If the given
// certificate has no Subject Key Identifier, one will be generated from its
// Public Key (if possible) by calling FromPublicKey.
func FromCertificate(cert *x509.Certificate) (SKID, error) {
	if cert == nil {
		return nil, ErrNoCertificate
	}

	if len(cert.SubjectKeyId) > 0 {
		return SKID(cert.SubjectKeyId), nil
	}

	return FromPublicKey(cert.PublicKey)
}

// FromCSR returns a SKID constructed using the public key contained within
// the given certificate request.  If csr is nil, then FromCSR returns a nil
// SKID and ErrNoCSR.
func FromCSR(csr *x509.CertificateRequest) (SKID, error) {
	if csr == nil {
		return nil, ErrNoCSR
	}

	return FromPublicKey(crypto.PublicKey(csr.PublicKey))
}

// FromPublicKey returns a SKID constructed from the given public key or nil
// and an error if pub is of an unsupported type.
//
// Currently supported key types are the same as for the standard library's
// x509.CreateCertificate function -- namely: *rsa.PublicKey, *ecdsa.PublicKey,
// and *ed25519.PublicKey.
//
// Additionally,
// FromPublicKey may also return an error if pub is of type *rsa.PublicKey and
// fails to encode as ASN.1.
func FromPublicKey(pub crypto.PublicKey) (SKID, error) {
	pkbytes, err := extractPublicKeyBytes(pub)
	if err != nil {
		return nil, err
	}

	// sha1.Sum returns a byte array...
	h := sha1.Sum(pkbytes)

	// ...but, we really want a slice.
	return SKID(h[:]), nil
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}

func extractPublicKeyBytes(pub crypto.PublicKey) ([]byte, error) {
	switch key := pub.(type) {
	case *rsa.PublicKey:
		return asn1.Marshal(pkcs1PublicKey{N: key.N, E: key.E})

	case *ecdsa.PublicKey:
		return elliptic.Marshal(key.Curve, key.X, key.Y), nil

	case ed25519.PublicKey:
		return key, nil

	default:
		return nil, errors.New("unsupported public key type")
	}
}
