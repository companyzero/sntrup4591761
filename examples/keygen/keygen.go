// Copyright (c) 2017 Company 0 LLC. All rights reserved.
// Use of this source code is governed by an ISC-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/companyzero/sntrup4591761"
)

func usageError() {
	fmt.Fprintf(os.Stderr,
		`keygen generates Streamlined NTRU Prime keypairs.

Usage:

	keygen <random> <pubkey> <privkey>
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

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	pkf, err := os.OpenFile(os.Args[2], flags, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer pkf.Close()

	skf, err := os.OpenFile(os.Args[3], flags, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer skf.Close()

	pk, sk, err := sntrup4591761.GenerateKey(rf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	pkf.Write(pk[:])
	skf.Write(sk[:])
}
