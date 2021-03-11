package main

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/yamachi4416/gootpo"
)

func getSpec() [][]string {
	return [][]string{
		{"59", "94287082", "SHA1", "12345678901234567890"},
		{"59", "46119246", "SHA256", "12345678901234567890123456789012"},
		{"59", "90693936", "SHA512", "1234567890123456789012345678901234567890123456789012345678901234"},
	}
}

func TestMain(t *testing.T) {
	in, out, err := bytes.Buffer{}, bytes.Buffer{}, bytes.Buffer{}
	stdin, stdout, stderr = &in, &out, &err

	execute := func(expected string, encode string, algo string, seed string, fd bool) {
		in.Reset()
		out.Reset()
		err.Reset()

		os.Args = []string{os.Args[0], "-e", encode, "-l", "8", "-a", algo}

		if fd {
			isTerminal = func() bool { return false }
			in.WriteString(seed)
		} else {
			isTerminal = func() bool { return true }
			os.Args = append(os.Args, seed)
		}

		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.SetOutput(stderr)

		opt = gootpo.DefaultOpt("")
		opt.Now = func() int64 { return 59 }

		status := 0
		exit = func(code int) { status = code }
		main()

		actual := strings.TrimSpace(out.String())
		if status != 0 || actual != expected {
			fmt.Fprintf(os.Stderr, "%v", opt)
			t.Fatalf("exit code is %d: '%s' is not equal to '%s'", status, actual, expected)
		}
	}

	t.Run("PLAIN/ARGS", func(t *testing.T) {
		for _, d := range getSpec() {
			execute(d[1], "PLAIN", d[2], d[3], false)
		}
	})

	t.Run("PLAIN/STDIN", func(t *testing.T) {
		for _, d := range getSpec() {
			execute(d[1], "PLAIN", d[2], d[3], true)
		}
	})

	t.Run("HEX", func(t *testing.T) {
		for _, d := range getSpec() {
			execute(d[1], "HEX", d[2], hex.EncodeToString([]byte(d[3])), false)
		}
	})

	t.Run("BASE32", func(t *testing.T) {
		for _, d := range getSpec() {
			execute(d[1], "BASE32", d[2], base32.StdEncoding.EncodeToString([]byte(d[3])), false)
		}
	})

	t.Run("USAGE", func(t *testing.T) {
		in.Reset()
		out.Reset()
		err.Reset()

		os.Args = []string{os.Args[0], "-h"}
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
		flag.CommandLine.SetOutput(stderr)

		main()
	})
}
