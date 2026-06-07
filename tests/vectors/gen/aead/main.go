package main

// Generates the big-endian-nonce ChaCha20Poly1305 KAT used by ts_control_noise.
//
// ts_control_noise's ChaCha20Poly1305BigEndian packs the 64-bit message counter
// into bytes [4..12] of the 12-byte nonce using big-endian order (matching Go
// tailscale's control/controlbase, which does binary.BigEndian.PutUint64(nonce[4:], counter)).
// This program produces the reference ciphertext+tag so the Rust side can assert
// byte-for-byte equality.

import (
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

type vector struct {
	Desc       string `json:"desc"`
	KeyHex     string `json:"key_hex"`
	Counter    uint64 `json:"counter"`
	NonceHex   string `json:"nonce_hex"`
	AdHex      string `json:"ad_hex"`
	PtHex      string `json:"pt_hex"`
	CtHex      string `json:"ct_hex"` // ciphertext || 16-byte tag (rust expects detached, we split)
	TagHex     string `json:"tag_hex"`
	CipherHex  string `json:"cipher_only_hex"`
}

func hex(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

func mustHex(s string) []byte {
	if len(s)%2 != 0 {
		panic("odd hex")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := unhexNib(s[i*2])
		lo := unhexNib(s[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func unhexNib(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	panic("bad hex nibble")
}

func beNonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func main() {
	cases := []struct {
		desc    string
		key     string
		counter uint64
		ad      string
		pt      string
	}{
		{
			desc:    "all-0x42 key, counter 7, fixed ad+pt",
			key:     "4242424242424242424242424242424242424242424242424242424242424242",
			counter: 7,
			ad:      "0102030405060708",
			pt:      "68656c6c6f20776972654b4154", // "hello wireKAT"
		},
		{
			desc:    "counter 0, empty ad, empty pt (tag-only)",
			key:     "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			counter: 0,
			ad:      "",
			pt:      "",
		},
		{
			desc:    "high counter 0xdeadbeefcafe1234, ad, longer pt",
			key:     "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00",
			counter: 0xdeadbeefcafe1234,
			ad:      "74732d636f6e74726f6c", // "ts-control"
			pt:      "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e",
		},
	}

	var out []vector
	for _, c := range cases {
		key := mustHex(c.key)
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			panic(err)
		}
		nonce := beNonce(c.counter)
		ad := mustHex(c.ad)
		pt := mustHex(c.pt)
		// Seal returns ciphertext||tag.
		sealed := aead.Seal(nil, nonce, pt, ad)
		var _ cipher.AEAD = aead
		tag := sealed[len(sealed)-chacha20poly1305.Overhead:]
		ctOnly := sealed[:len(sealed)-chacha20poly1305.Overhead]
		out = append(out, vector{
			Desc:      c.desc,
			KeyHex:    c.key,
			Counter:   c.counter,
			NonceHex:  hex(nonce),
			AdHex:     c.ad,
			PtHex:     c.pt,
			CtHex:     hex(sealed),
			TagHex:    hex(tag),
			CipherHex: hex(ctOnly),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
