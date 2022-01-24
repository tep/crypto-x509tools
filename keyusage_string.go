package x509tools

import (
	"crypto/x509"
	"sort"
	"strings"
)

func KeyUsageString(ku x509.KeyUsage) string {
	var out []string

	kum := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "DigitalSignature",
		x509.KeyUsageContentCommitment: "ContentCommitment",
		x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
		x509.KeyUsageDataEncipherment:  "DataEncipherment",
		x509.KeyUsageKeyAgreement:      "KeyAgreement",
		x509.KeyUsageCertSign:          "CertSign",
		x509.KeyUsageCRLSign:           "CRLSign",
		x509.KeyUsageEncipherOnly:      "EncipherOnly",
		x509.KeyUsageDecipherOnly:      "DecipherOnly",
	}

	for k, s := range kum {
		if ku&k != 0 {
			out = append(out, s)
		}
	}

	sort.Strings(out)

	return strings.Join(out, "|")
}
