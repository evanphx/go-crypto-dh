
package dh

import (
  "math/big"
  "errors"
  "math/rand"
)

var bigZero = big.NewInt(0)
var bigOne  = big.NewInt(1)
var bigTwo  = big.NewInt(2)

type PublicKey struct {
  P  *big.Int
  G  *big.Int
  GX *big.Int
}

type Group struct {
  P *big.Int
  G *big.Int
}

var (
  group1p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"

  group14p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

func makeGroup(p string, g int64) *Group {
  P, err := new(big.Int).SetString(p, 16)
  if !err {
    return nil
  }

  G := new(big.Int).SetInt64(g)

  return &Group { P, G }
}

var errPublicParams = errors.New("crypto/dh: missing public parameters")
var group1  = makeGroup(group1p, 2)
var group14 = makeGroup(group14p, 2)

func checkPub(pub* PublicKey) error {
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

func MakeKey() (priv* PrivateKey) {
  priv = new(PrivateKey)

  priv.P = group1.P
  priv.G = group1.G

  q := new(big.Int).Sub(priv.P, bigOne)
  q.Div(q, bigTwo)

  rand := rand.New(rand.NewSource(0)) // TODO change me!

  priv.X  = new(big.Int).Rand(rand, q)
  priv.GX = new(big.Int).Exp(priv.G, priv.X, priv.P)

  return
}

func (priv* PrivateKey) ComputeSecret(pub* PublicKey) *big.Int {
  ret := new(big.Int)

  ret.Exp(pub.GX, priv.X, priv.P)

  return ret
}

// func GenerateKey(random io.Reader, bits int) (priv *PrivateKey, err error) {
  // priv = new(PrivateKey)

// }
