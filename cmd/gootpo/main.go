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
	"os"
	"strings"

	"github.com/yamachi4416/gootpo"
	"golang.org/x/term"
)

var (
	algo   = "SHA1"
	encode = ""
	opt    = gootpo.DefaultOpt("")
)

func usage() {
	fmt.Fprintln(os.Stderr, "Usage of gootpo:")
	fmt.Fprintln(os.Stderr, "	gootpo Seed")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.StringVar(&algo, "a", algo, "Algorithm [SHA1|SHA256|SHA512]")
	flag.StringVar(&encode, "e", "PLAIN", "Input Encoding [HEX|BASE32|PLAIN]")
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
		flag.Usage()
	}

	switch strings.ToUpper(encode) {
	case "HEX":
		opt.Decoder = hex.DecodeString
	case "BASE32":
		opt.Decoder = base32.StdEncoding.DecodeString
	case "PLAIN":
	default:
		flag.Usage()
	}

	if flag.NArg() > 0 {
		opt.Seed = flag.Arg(0)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		flag.Usage()
	} else if s := bufio.NewScanner(os.Stdin); s.Scan() {
		opt.Seed = s.Text()
	} else {
		flag.Usage()
	}

	if code, err := gootpo.TOTP(opt); err == nil {
		fmt.Println(code)
	} else {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
