package dh

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"math/big"
	"reflect"
)

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)
var bigTwo = big.NewInt(2)

type PublicKey struct {
	P  *big.Int
	G  *big.Int
	GX *big.Int
}

type Group struct {
	P *big.Int
	G *big.Int
}

func (grp *Group) Print() {
	fmt.Printf("P=%x (bits:%d)\nG=%x\n", grp.P, grp.P.BitLen(), grp.G)
	return
}

var (
	// These 2 groups are used in SSH and provide good builtin groups

	// diffie-hellman-group1-sha1
	group1p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

	// diffie-hellman-group14-sha1
	group14p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

func makeGroup(p string, g int64) *Group {
	P, err := new(big.Int).SetString(p, 16)
	if !err {
		return nil
	}

	G := new(big.Int).SetInt64(g)

	return &Group{P, G}
}

type dhparams struct {
	P *big.Int
	G *big.Int
}

var errBadPEM = errors.New("crypto/dh: pem file did not contain dh params")

func LoadPEM(path string) (grp *Group, err error) {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)

	pv := reflect.New(reflect.TypeOf(Group1).Elem())
	val := pv.Interface()

	_, err = asn1.Unmarshal(block.Bytes, val)

	if err != nil {
		return nil, err
	}

	x, ok := val.(*Group)

	if !ok {
		return nil, errBadPEM
	}

	return x, nil
}

var errPublicParams = errors.New("crypto/dh: missing public parameters")
var Group1 = makeGroup(group1p, 2)
var Group14 = makeGroup(group14p, 2)

func checkPub(pub *PublicKey) error {
	if pub.P == nil {
		return errPublicParams
	}

	if pub.G == nil {
		return errPublicParams
	}

	return nil
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

func (priv *PrivateKey) Validate() error {
	if err := checkPub(&priv.PublicKey); err != nil {
		return err
	}

	return nil
}

type SlimPublicKey struct {
	GX *big.Int
}

func (priv *PrivateKey) SlimPub() *SlimPublicKey {
	return &SlimPublicKey{priv.GX}
}

func MakeKey(rr io.Reader, grp *Group) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)

	priv.P = grp.P
	priv.G = grp.G

	q := new(big.Int).Sub(priv.P, bigOne)
	q.Div(q, bigTwo)

	priv.X, err = rand.Int(rr, q)

	if err != nil {
		return nil, err
	}

	priv.GX = new(big.Int).Exp(priv.G, priv.X, priv.P)

	return
}

type Secret struct {
	S big.Int
}

func (sec *Secret) Cmp(oth *Secret) int {
	return sec.S.Cmp(&oth.S)
}

func (sec *Secret) Bytes() []byte {
	return sec.S.Bytes()
}

var errBadCount = errors.New("crypto/dh: Count not multiple of source")

func (sec *Secret) Hash(h hash.Hash) []byte {
	return h.Sum(sec.S.Bytes())
}

// Implementation of NIST SP 800-56A, Section 5.8

func (sec *Secret) DeriveKey(hf func() hash.Hash, keylen int, other []byte) []byte {
	h := hf()

	reps := keylen / h.Size()

	if keylen%h.Size() != 0 {
		reps += 1
	}

	var buf [4]byte

	var dk bytes.Buffer

	for counter := 1; counter <= reps; counter++ {
		buf[0] = byte(counter >> 24)
		buf[1] = byte(counter >> 16)
		buf[2] = byte(counter >> 8)
		buf[3] = byte(counter)

		h.Write(buf[:])
		h.Write(sec.S.Bytes())
		h.Write(other)
		dk.Write(h.Sum(nil))

		h = hf()
	}

	return dk.Bytes()[:keylen]
}

func (pub *PublicKey) ComputeSecret(priv *PrivateKey) *Secret {
	ret := new(Secret)

	ret.S.Exp(pub.GX, priv.X, priv.P)

	return ret
}

func (pub *SlimPublicKey) ComputeSecret(priv *PrivateKey) *Secret {
	ret := new(Secret)

	ret.S.Exp(pub.GX, priv.X, priv.P)

	return ret
}

// func GenerateKey(random io.Reader, bits int) (priv *PrivateKey, err error) {
// priv = new(PrivateKey)

// }
