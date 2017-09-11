// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"github.com/companyzero/sntrup4591761"
	"io"
	"os"
)

func usageError() {
	fmt.Fprintf(os.Stderr,
		`encap generates a random Streamlined NTRU Prime shared key and encapsulates it
in a ciphertext. The ciphertext is stored in <ciphertext> (a file) while the
shared key is printed on stdout in hexadecimal notation.

Usage:

	encap <random> <pubkey> <ciphertext>
`)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 4 {
		usageError()
	}

	rf, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	defer rf.Close()
	pkf, err := os.Open(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer pkf.Close()

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	cf, err := os.OpenFile(os.Args[3], flags, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer cf.Close()

	pk := new([sntrup4591761.PublicKeySize]byte)
	_, err = io.ReadFull(pkf, pk[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	c, k, err := sntrup4591761.Encapsulate(rf, pk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	cf.Write(c[:])

	for i, v := range k {
		if i != 0 {
			fmt.Printf(":")
		}
		fmt.Printf("%02x", v)
	}
	fmt.Printf("\n")
}
