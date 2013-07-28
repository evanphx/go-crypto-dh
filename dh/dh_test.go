
package dh

import (
	"testing"
)

func TestKey(t *testing.T) {
  key := MakeKey()

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
  k1 := MakeKey()
  k2 := MakeKey()

  s1 := k1.ComputeSecret(&k2.PublicKey)
  s2 := k2.ComputeSecret(&k1.PublicKey)

  if s1.Cmp(s2) != 0 {
    t.Errorf("Secrets not comuting")
  }
}
