package skid

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
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
	entries, err := os.ReadDir(testdataDir)
	if err != nil {
		return nil, err
	}

	var out []testdata

	for _, entry := range entries {
		var (
			name string
			err  error
			td   testdata
		)

		if name = checkFile(entry); name == "" {
			continue
		}

		if td, err = parseTestdataFile(name); err != nil {
			return nil, fmt.Errorf("parsing file %q: %w", name, err)
		}

		out = append(out, td)
	}

	return out, nil
}

func checkFile(entry fs.DirEntry) string {
	if !entry.Type().IsRegular() {
		return ""
	}

	name := entry.Name()
	if filepath.Ext(name) != ".yaml" {
		return ""
	}

	return filepath.Join(testdataDir, name)
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

	for _, text := range []string{td.PubKey, td.CSR, td.Cert} {
		switch text {
		case td.PubKey:
			td.pubkey, err = parsePublicKey(td.PubKey)

		case td.CSR:
			td.req, err = parseCertRequest(td.CSR)

		case td.Cert:
			td.cert, err = parseCertificate(td.Cert)
		}

		if err != nil {
			return td, err
		}
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
