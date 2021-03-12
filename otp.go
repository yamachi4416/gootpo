package gootpo

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"time"
)

// Opt is option
type Opt struct {
	Seed     string
	Length   int
	Interval int
	Offset   int
	Algo     func() hash.Hash
	Now      func() int64
	Decoder  func(string) ([]byte, error)
}

// DefaultOpt default option
func DefaultOpt(seed string) *Opt {
	return &Opt{
		Seed:     seed,
		Length:   6,
		Interval: 30,
		Offset:   0,
		Algo:     sha1.New,
		Decoder:  func(s string) ([]byte, error) { return []byte(s), nil },
	}
}

func genHS(count uint64, opt *Opt) ([]byte, error) {
	c := make([]byte, 8)

	binary.BigEndian.PutUint64(c, count)

	seed, err := opt.Decoder(opt.Seed)
	if err != nil {
		return nil, err
	}

	m := hmac.New(opt.Algo, seed)
	m.Write(c)

	return m.Sum(nil), nil
}

func truncate(hs []byte) int {
	o := int(hs[len(hs)-1] & 0xF)
	return ((int(hs[o]) & 0x7F) << 24) |
		((int(hs[o+1]) & 0xFF) << 16) |
		((int(hs[o+2]) & 0xFF) << 8) |
		(int(hs[o+3]) & 0xFF)
}

// HOTP calculating the HOTP
func HOTP(count uint64, opt *Opt) (string, error) {
	hs, err := genHS(count, opt)
	if err != nil {
		return "", err
	}

	n := truncate(hs)
	f := fmt.Sprintf("%%0%dd", opt.Length)

	return fmt.Sprintf(f, n%int(math.Pow10(opt.Length))), nil
}

// TOTP calculating the TOTP
func TOTP(opt *Opt) (string, error) {
	n := time.Now().Unix()
	if opt.Now != nil {
		n = opt.Now()
	}

	count := uint64((n - int64(opt.Offset)) / int64(opt.Interval))

	return HOTP(count, opt)
}
