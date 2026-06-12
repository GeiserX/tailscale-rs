package main

// Generates the NaCl box (X25519 + XSalsa20-Poly1305) KAT used to cross-validate
// the pure-Rust `crypto_box::SalsaBox` against Go's `golang.org/x/crypto/nacl/box`.
//
// Both the disco NAT-traversal seal (ts_disco_protocol) and the DERP client/server
// handshake (ts_derp) use `crypto_box::SalsaBox::new(&their_pub, &my_secret)` with a
// 24-byte nonce — i.e. exactly NaCl `box`. Go's disco (tailscale `disco`) and DERP
// both use `nacl/box`, so the wire bytes MUST match or two Rust nodes talk only to
// each other and silently fail against every Go peer + Go DERP server.
//
// This program seals fixed plaintexts under fixed X25519 keypairs + fixed 24-byte
// nonces and emits, for each vector, the sealing keypair material plus the
// ciphertext||tag, so the Rust side asserts byte-for-byte equality in BOTH
// directions (Rust seals == Go sealed; Rust opens Go's sealed bytes).
//
// nacl/box.Seal(out, message, &nonce, peersPublicKey, privateKey) returns the
// NaCl wire layout: the 16-byte Poly1305 tag FIRST, then the ciphertext
// (tag || ciphertext) — the standard crypto_secretbox/NaCl convention.

import (
	"encoding/json"
	"os"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type vector struct {
	Desc string `json:"desc"`
	// The sender seals with senderPriv to recipientPub; the recipient opens with
	// recipientPriv from senderPub. Both keypairs are emitted so the Rust KAT can
	// drive seal (sender side) and open (recipient side).
	SenderPrivHex    string `json:"sender_priv_hex"`
	SenderPubHex     string `json:"sender_pub_hex"`
	RecipientPrivHex string `json:"recipient_priv_hex"`
	RecipientPubHex  string `json:"recipient_pub_hex"`
	NonceHex         string `json:"nonce_hex"` // 24 bytes
	PtHex            string `json:"pt_hex"`
	// box.Seal output: 16-byte Poly1305 tag || ciphertext (the NaCl layout; the
	// disco layer stores the tag detached in its header, but this is the canonical
	// nacl/box wire byte string).
	SealedHex string `json:"sealed_hex"`
}

func hexstr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
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

func mustHex(s string) []byte {
	if len(s)%2 != 0 {
		panic("odd hex")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = unhexNib(s[i*2])<<4 | unhexNib(s[i*2+1])
	}
	return out
}

// key32 copies a hex-decoded 32-byte slice into the fixed array nacl/box wants.
func key32(s string) *[32]byte {
	b := mustHex(s)
	if len(b) != 32 {
		panic("key not 32 bytes")
	}
	var k [32]byte
	copy(k[:], b)
	return &k
}

func nonce24(s string) *[24]byte {
	b := mustHex(s)
	if len(b) != 24 {
		panic("nonce not 24 bytes")
	}
	var n [24]byte
	copy(n[:], b)
	return &n
}

// scalarBaseMult derives the X25519 public key for a private scalar, the same
// operation nacl/box performs internally to obtain the sender's public key.
func scalarBaseMult(priv *[32]byte) [32]byte {
	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var pub [32]byte
	copy(pub[:], pubSlice)
	return pub
}

func main() {
	// Fixed X25519 scalars (the NaCl box clamps internally, so any 32 bytes are a
	// valid private key). Distinct fill bytes keep the two keypairs unambiguous.
	cases := []struct {
		desc          string
		senderPriv    string
		recipientPriv string
		nonce         string
		pt            string
	}{
		{
			desc:          "empty plaintext (tag-only), all-0x11 sender / 0x22 recipient",
			senderPriv:    "1111111111111111111111111111111111111111111111111111111111111111",
			recipientPriv: "2222222222222222222222222222222222222222222222222222222222222222",
			nonce:         "000102030405060708090a0b0c0d0e0f1011121314151617",
			pt:            "",
		},
		{
			desc:          "short disco-like plaintext",
			senderPriv:    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			recipientPriv: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			nonce:         "fedcba9876543210fedcba9876543210fedcba9876543210",
			pt:            "78797a7a79", // "xyzzy"
		},
		{
			desc:          "longer plaintext (DERP client-info-like JSON blob)",
			senderPriv:    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			recipientPriv: "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
			nonce:         "0000000000000000000000000000000000000000deadbeef",
			pt:            "7b2276657273696f6e223a322c226d65736853657373696f6e223a747275657d", // {"version":2,"meshSession":true}
		},
	}

	var out []vector
	for _, c := range cases {
		senderPriv := key32(c.senderPriv)
		recipientPriv := key32(c.recipientPriv)
		nonce := nonce24(c.nonce)
		pt := mustHex(c.pt)

		// Derive the public keys the same way nacl/box does (X25519 over the basepoint).
		senderPub := scalarBaseMult(senderPriv)
		recipientPub := scalarBaseMult(recipientPriv)

		// Seal: sender seals to recipientPub with senderPriv.
		sealed := box.Seal(nil, pt, nonce, &recipientPub, senderPriv)

		out = append(out, vector{
			Desc:             c.desc,
			SenderPrivHex:    c.senderPriv,
			SenderPubHex:     hexstr(senderPub[:]),
			RecipientPrivHex: c.recipientPriv,
			RecipientPubHex:  hexstr(recipientPub[:]),
			NonceHex:         c.nonce,
			PtHex:            c.pt,
			SealedHex:        hexstr(sealed),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
