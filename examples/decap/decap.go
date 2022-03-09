// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/companyzero/sntrup4591761"
)

func usageError() {
	fmt.Fprintf(os.Stderr,
		`decap retrieves a Streamlined NTRU Prime shared key from a ciphertext. The
shared key is printed on stdout in hexadecimal notation.

Usage:

	decap <privkey> <ciphertext>
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 3 {
		usageError()
	}

	skf, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer skf.Close()

	cf, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer cf.Close()

	sk := new(sntrup4591761.PrivateKey)
	_, err = io.ReadFull(skf, sk[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	c := new(sntrup4591761.Ciphertext)
	_, err = io.ReadFull(cf, c[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	k, ok := sntrup4591761.Decapsulate(c, sk)
	if ok != 1 {
		fmt.Fprintf(os.Stderr, "decapsulation error\n")
		os.Exit(1)
	}

	for i, v := range k {
		if i != 0 {
			fmt.Printf(":")
		}
		fmt.Printf("%02x", v)
	}
	fmt.Printf("\n")
}
