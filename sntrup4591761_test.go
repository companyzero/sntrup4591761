// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

package sntrup4591761

import (
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/companyzero/sntrup4591761/r3"
	"github.com/companyzero/sntrup4591761/zx"
)

// Auxiliary function to compare two byte slices.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// testKeyDerivation ensures that, for a given pair (f, g), the generated
// public and private keys match those created by Sage.
func testKeyDerivation(t *testing.T, params *[7][]byte) {
	f := zx.Decode(params[0])
	g := zx.Decode(params[1])
	epk := params[3]
	esk := params[4]
	gr := new([761]int8)
	r3.Reciprocal(gr, g)
	pk, sk := deriveKey(f, g, gr)
	if !equal(epk, pk[:]) {
		t.Fatalf("wrong public key; expected %v, got %v", epk, pk)
	}
	if !equal(esk, sk[:]) {
		t.Fatalf("wrong private key; expected %v, got %v", epk, pk)
	}
}

// testEncapsulation ensures that, given a random t-small element r, the
// generated ciphertext and shared key match those created by Sage.
func testEncapsulation(t *testing.T, params *[7][]byte) {
	r := zx.Decode(params[2])
	pk := new(PublicKey)
	copy(pk[:], params[3])
	ec := params[5]
	ek := params[6]
	c, k := createCipher(r, pk)
	if !equal(ec, c[:]) {
		t.Fatalf("wrong ciphertext; expected %v, got %v", ec, c)
	}
	if !equal(ek, k[:]) {
		t.Fatalf("wrong shared key; expected %v, got %v", ek, k)
	}
}

// testDecapsulation ensures that, given a ciphertext and a private key, the
// derived shared key matches the one calculated by Sage.
func testDecapsulation(t *testing.T, params *[7][]byte) {
	sk := new(PrivateKey)
	copy(sk[:], params[4])
	c := new(Ciphertext)
	copy(c[:], params[5])
	ek := params[6]
	k, ok := Decapsulate(c, sk)
	if ok != 1 {
		t.Fatalf("Decapsulation error")
	}
	if !equal(ek, k[:]) {
		t.Fatalf("wrong ciphertext; expected %v, got %v", ek, k)
	}
}

// TestSage reads in a batch of <f,g,r,pk,sk,c,k> tuples and verifies that the
// key generation, encapsulation and decapsulation procedures provide identical
// results as the Sage implementation of NTRU Prime.
func TestSage(t *testing.T) {
	testDataZ, err := os.Open("testdata/sage128.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer testDataZ.Close()
	testData, err := gzip.NewReader(testDataZ)
	if err != nil {
		t.Fatal(err)
	}
	defer testData.Close()

	in := bufio.NewReaderSize(testData, 1<<14)
	lineNo := 0
	for {
		lineNo++
		lineBytes, isPrefix, err := in.ReadLine()
		if isPrefix {
			t.Fatal("bufio buffer too small")
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("error reading test data: %s", err)
		}
		t.Logf("processing line %d\n", lineNo)

		line := string(lineBytes)
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			t.Fatalf("bad number of parts: %d", len(parts))
		}
		params := new([7][]byte)
		for i, v := range parts {
			params[i], err = hex.DecodeString(v)
			if err != nil {
				t.Fatalf("error decoding entry %d", i+1)
			}
		}
		testKeyDerivation(t, params)
		testEncapsulation(t, params)
		testDecapsulation(t, params)
	}
}
