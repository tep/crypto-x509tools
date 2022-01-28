package skid

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const testdataDir = "testdata"

var allTestdata []testdata

func init() {
	var err error
	if allTestdata, err = loadTestdata(); err != nil {
		panic(err)
	}
}

type testdata struct {
	name   string
	pubkey crypto.PublicKey
	req    *x509.CertificateRequest
	cert   *x509.Certificate

	Bytes  []byte `yaml:"skid"`
	Text   string `yaml:"string"`
	PubKey string `yaml:"public-key"`
	CSR    string `yaml:"request"`
	Cert   string `yaml:"certificate"`
}

func loadTestdata() ([]testdata, error) {
	files, err := os.ReadDir(testdataDir)
	if err != nil {
		return nil, err
	}

	var out []testdata

	for _, dent := range files {
		if !dent.Type().IsRegular() {
			continue
		}

		name := dent.Name()
		if filepath.Ext(name) != ".yaml" {
			continue
		}

		td, err := parseTestdataFile(filepath.Join(testdataDir, name))
		if err != nil {
			return nil, fmt.Errorf("parsing file %q: %w", name, err)
		}

		out = append(out, td)
	}

	return out, nil
}

func parseTestdataFile(filename string) (testdata, error) {
	var td testdata

	data, err := os.ReadFile(filename)
	if err != nil {
		return td, err
	}

	if err := yaml.Unmarshal(data, &td); err != nil {
		return td, err
	}

	td.name = strings.TrimSuffix(filepath.Base(filename), ".yaml")

	if td.pubkey, err = parsePublicKey(td.PubKey); err != nil {
		return td, err
	}

	if td.req, err = parseCertRequest(td.CSR); err != nil {
		return td, err
	}

	if td.cert, err = parseCertificate(td.Cert); err != nil {
		return td, err
	}

	return td, nil
}

func parsePublicKey(text string) (crypto.PublicKey, error) {
	blk, _ := pem.Decode([]byte(text))
	if blk == nil {
		return nil, errors.New("pem decode failed")
	}

	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse public key: %w", err)
	}

	return key, nil
}

func parseCertRequest(text string) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode([]byte(text))
	if blk == nil {
		return nil, errors.New("pem decode failed")
	}

	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse certificate request: %w", err)
	}

	return csr, nil
}

func parseCertificate(text string) (*x509.Certificate, error) {
	blk, _ := pem.Decode([]byte(text))
	if blk == nil {
		return nil, errors.New("pem decode failed")
	}

	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse x509 certificate: %w", err)
	}

	return cert, nil
}
