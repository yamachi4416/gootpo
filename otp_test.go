package gootpo

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
)

const Seed16 = "12345678901234567890"
const Seed32 = "12345678901234567890123456789012"
const Seed64 = "1234567890123456789012345678901234567890123456789012345678901234"

func getSpec1() [][]string {
	return [][]string{
		{"0", "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", "755224"},
		{"1", "75a48a19d4cbe100644e8ac1397eea747a2d33ab", "287082"},
		{"2", "0bacb7fa082fef30782211938bc1c5e70416ff44", "359152"},
		{"3", "66c28227d03a2d5529262ff016a1e6ef76557ece", "969429"},
		{"4", "a904c900a64b35909874b33e61c5938a8e15ed1c", "338314"},
		{"5", "a37e783d7b7233c083d4f62926c7a25f238d0316", "254676"},
		{"6", "bc9cd28561042c83f219324d3c607256c03272ae", "287922"},
		{"7", "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", "162583"},
		{"8", "1b3c89f65e6c9e883012052823443f048b4332db", "399871"},
		{"9", "1637409809a679dc698207310c8c7fc07290d9e5", "520489"},
	}
}

func getSpec2() [][]string {
	return [][]string{
		{"59", "94287082", "SHA1"},
		{"59", "46119246", "SHA256"},
		{"59", "90693936", "SHA512"},
		{"1111111109", "07081804", "SHA1"},
		{"1111111109", "68084774", "SHA256"},
		{"1111111109", "25091201", "SHA512"},
		{"1111111111", "14050471", "SHA1"},
		{"1111111111", "67062674", "SHA256"},
		{"1111111111", "99943326", "SHA512"},
		{"1234567890", "89005924", "SHA1"},
		{"1234567890", "91819424", "SHA256"},
		{"1234567890", "93441116", "SHA512"},
		{"2000000000", "69279037", "SHA1"},
		{"2000000000", "90698825", "SHA256"},
		{"2000000000", "38618901", "SHA512"},
		{"20000000000", "65353130", "SHA1"},
		{"20000000000", "77737706", "SHA256"},
		{"20000000000", "47863826", "SHA512"},
	}
}

func TestGenHS(t *testing.T) {
	for _, d := range getSpec1() {
		count, expected := d[0], d[1]
		c, _ := strconv.ParseUint(count, 10, 64)
		if hs, err := genHS(c, DefaultOpt(Seed16)); err != nil {
			t.Fatal(err)
		} else {
			actual := hex.EncodeToString(hs)
			if actual != expected {
				t.Fatalf("%s is not equal to %s", actual, expected)
			}
		}
	}
}

func TestHOTP(t *testing.T) {
	for _, d := range getSpec1() {
		count, expected := d[0], d[2]
		c, _ := strconv.ParseUint(count, 10, 64)
		if actual, err := HOTP(c, DefaultOpt(Seed16)); err != nil {
			t.Fatal(err)
		} else if actual != expected {
			t.Fatalf("%s is not equal to %s", actual, expected)
		}
	}
}

func TestHOTPError(t *testing.T) {
	opt := DefaultOpt("")
	opt.Decoder = func(s string) ([]byte, error) {
		return nil, errors.New("Decoder Error")
	}

	if _, err := HOTP(0, opt); err == nil {
		t.Fatal()
	} else if err.Error() != "Decoder Error" {
		t.Fatal(err)
	}
}

func TestTOTP(t *testing.T) {
	for _, d := range getSpec2() {
		var opt *Opt
		stime, expected, algo := d[0], d[1], d[2]

		switch algo {
		case "SHA1":
			opt = DefaultOpt(Seed16)
			opt.Algo = sha1.New
		case "SHA256":
			opt = DefaultOpt(Seed32)
			opt.Algo = sha256.New
		case "SHA512":
			opt = DefaultOpt(Seed64)
			opt.Algo = sha512.New
		default:
			t.Fatal()
		}

		utime, _ := strconv.ParseInt(stime, 10, 64)
		opt.Length = 8
		opt.Now = func() int64 { return utime }

		if actual, err := TOTP(opt); err != nil {
			t.Fatal(err)
		} else if actual != expected {
			t.Fatalf("%s is not equal to %s", actual, expected)
		}
	}
}
