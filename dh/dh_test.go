package dh

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"io"
	"testing"
)

func TestKey(t *testing.T) {
	key, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	if !key.P.ProbablyPrime(20) {
		t.Errorf("P is not prime")
	}

	if key.G.Cmp(key.P) == 1 {
		t.Errorf("G is greater than P")
	}

	if key.X.Cmp(key.P) == 1 {
		t.Errorf("X is greater than P")
	}
}

func TestAlgo(t *testing.T) {
	k1, e1 := MakeKey(rand.Reader, Group1)
	k2, e2 := MakeKey(rand.Reader, Group1)

	if e1 != nil {
		panic(e1)
	}

	if e2 != nil {
		panic(e2)
	}

	s1 := k2.ComputeSecret(k1)
	s2 := k1.ComputeSecret(k2)

	if s1.Cmp(s2) != 0 {
		t.Errorf("Secrets not comuting")
	}
}

func TestSlimPub(t *testing.T) {
	k1, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	slim := k1.SlimPub()

	if k1.GX.Cmp(slim.GX) != 0 {
		t.Errorf("Slim key doesn't have GX")
	}

	k2, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	s1 := slim.ComputeSecret(k2)
	s2 := k2.SlimPub().ComputeSecret(k1)

	if s1.Cmp(s2) != 0 {
		t.Errorf("Secrets not comuting")
	}
}

func TestAsCryptoKey(t *testing.T) {
	k1, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	k2, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	key1 := k1.PublicKey.ComputeSecret(k2)

	plaintext := []byte("some plaintext")

	ckey := key1.DeriveKey(sha256.New, 16, []byte(""))

	block, err := aes.NewCipher(ckey)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// CTR mode is the same for both encryption and decryption, so we can
	// also decrypt that ciphertext with NewCTR.

	plaintext2 := make([]byte, len(plaintext))
	key2 := k2.PublicKey.ComputeSecret(k1)

	ckey2 := key2.DeriveKey(sha256.New, 16, []byte(""))

	block2, err := aes.NewCipher(ckey2)

	stream = cipher.NewCTR(block2, iv)
	stream.XORKeyStream(plaintext2, ciphertext[aes.BlockSize:])

	if bytes.Compare(plaintext, plaintext2) != 0 {
		t.Errorf("keys didn't roundtrip encryption correctly")
	}
}

func TestDeriveKeyUnique(t *testing.T) {
	k1, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	k2, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	k3, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	k4, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	s1 := k1.PublicKey.ComputeSecret(k2)
	s2 := k3.PublicKey.ComputeSecret(k4)

	y1 := s1.DeriveKey(sha256.New, 32, []byte(""))
	y2 := s2.DeriveKey(sha256.New, 32, []byte(""))

	if bytes.Equal(y1, y2) {
		t.Errorf("Derive key not producing unique keys!")
	}
}

func TestDeriveKey(t *testing.T) {
	k1, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	k2, err := MakeKey(rand.Reader, Group1)

	if err != nil {
		panic(err)
	}

	s := k1.PublicKey.ComputeSecret(k2)

	if len(s.DeriveKey(sha256.New, 22, []byte(""))) != 22 {
		t.Errorf("Wrong sized return slice")
	}

	if !bytes.Equal(s.DeriveKey(sha256.New, 16, []byte("")),
		s.DeriveKey(sha256.New, 16, []byte(""))) {
		t.Errorf("Multiple calls with same data give different keys")
	}

	if bytes.Equal(s.DeriveKey(sha256.New, 16, []byte("")),
		s.DeriveKey(sha256.New, 32, []byte(""))) {
		t.Errorf("keys that should be different are not")
	}

	if bytes.Equal(s.DeriveKey(sha256.New, 16, []byte("blah")),
		s.DeriveKey(sha256.New, 16, []byte(""))) {
		t.Errorf("keys that should be different are not")
	}

	if bytes.Equal(s.DeriveKey(sha1.New, 16, []byte("")),
		s.DeriveKey(sha256.New, 16, []byte(""))) {
		t.Errorf("keys that should be different are not")
	}
}

func TestLoadPEM(t *testing.T) {
	grp, err := LoadPEM("./dh512.pem")

	if err != nil {
		panic(err)
	}

	if !grp.P.ProbablyPrime(20) {
		t.Errorf("P isn't prime")
	}

	if grp.P.BitLen() != 512 {
		t.Errorf("P isn't 512 bits")
	}
}
