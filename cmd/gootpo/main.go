package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yamachi4416/gootpo"
	"golang.org/x/term"
)

var (
	algo   = "SHA1"
	encode = "PLAIN"
	opt    = gootpo.DefaultOpt("")
)

var (
	exit                 = os.Exit
	stdin      io.Reader = os.Stdin
	stderr     io.Writer = os.Stderr
	stdout     io.Writer = os.Stdout
	isTerminal           = func() bool {
		return term.IsTerminal(int(os.Stdin.Fd()))
	}
)

func printUsage() {
	fmt.Fprintln(stderr, "Usage of gootpo:")
	fmt.Fprintln(stderr, "	gootpo Seed")
	flag.PrintDefaults()
}

func usage() int {
	printUsage()
	return 2
}

func program() int {
	flag.Usage = printUsage
	flag.StringVar(&algo, "a", algo, "Algorithm [SHA1|SHA256|SHA512]")
	flag.StringVar(&encode, "e", encode, "Input Encoding [HEX|BASE32|PLAIN]")
	flag.IntVar(&opt.Interval, "i", opt.Interval, "Interval")
	flag.IntVar(&opt.Length, "l", opt.Length, "Length")
	flag.IntVar(&opt.Offset, "o", opt.Offset, "Offset (default 0)")
	flag.Parse()

	switch strings.ToUpper(algo) {
	case "SHA1":
		opt.Algo = sha1.New
	case "SHA256":
		opt.Algo = sha256.New
	case "SHA512":
		opt.Algo = sha512.New
	default:
		return usage()
	}

	switch strings.ToUpper(encode) {
	case "HEX":
		opt.Decoder = hex.DecodeString
	case "BASE32":
		opt.Decoder = base32.StdEncoding.DecodeString
	case "PLAIN":
	default:
		return usage()
	}

	if flag.NArg() > 0 {
		opt.Seed = flag.Arg(0)
	} else if isTerminal() {
		return usage()
	} else if s := bufio.NewScanner(stdin); s.Scan() {
		opt.Seed = s.Text()
	} else {
		return usage()
	}

	if code, err := gootpo.TOTP(opt); err == nil {
		fmt.Fprintln(stdout, code)
	} else {
		fmt.Fprintln(stderr, err)
		return 2
	}

	return 0
}

func main() {
	exit(program())
}
