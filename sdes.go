package dtls

import (
	"encoding/base64"
	"github.com/icn-team/dtls/v2/pkg/crypto/prf"
)

type SDES struct {
	masterSecret []byte
	cipherSuite  CipherSuite
}

func NewSDES(encodedSecret string, ciphersuiteID CipherSuiteID) (*SDES, error) {
	sdes := &SDES{}

	masterSecret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil {
		return nil, err
	}

	sdes.masterSecret = masterSecret
	sdes.cipherSuite = cipherSuiteForID(ciphersuiteID, nil)

	return sdes, nil
}

// ExportKeyingMaterial returns length bytes of exported key material in a new
// slice.
func (s *SDES) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	seed := []byte(label)
	return prf.PHash(s.masterSecret, seed, length, s.cipherSuite.HashFunc())
}
