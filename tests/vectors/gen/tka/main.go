package main

// Emits a TKA golden: the exact CBOR serialization and BLAKE2s-256 SigHash that the
// REAL tailscale.com/tka package produces for fixed NodeKeySignature values. The Rust
// ts_tka encoder + sig_hash() must reproduce these bytes, or the CTAP2-CBOR ordering /
// nonempty-bytes / SigHash-preimage logic diverges from Go on the wire.

import (
	"encoding/json"
	"fmt"
	"os"

	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

func hexstr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

type golden struct {
	Desc        string `json:"desc"`
	SigKind     int    `json:"sig_kind"`
	PubkeyHex   string `json:"pubkey_hex"`
	KeyIDHex    string `json:"key_id_hex"`
	SigHex      string `json:"signature_hex"`
	WrapHex     string `json:"wrapping_pubkey_hex,omitempty"`
	CBORHex     string `json:"cbor_full_hex"`      // Serialize(): full CBOR incl. signature
	SigHashHex  string `json:"sig_hash_hex"`       // SigHash(): BLAKE2s-256 of CBOR w/ signature nil'd
}

func dump(desc string, nks tka.NodeKeySignature) golden {
	full := nks.Serialize() // tkatype.MarshaledSignature ([]byte)
	sh := nks.SigHash()     // [blake2s.Size]byte
	g := golden{
		Desc:       desc,
		SigKind:    int(nks.SigKind),
		PubkeyHex:  hexstr(nks.Pubkey),
		KeyIDHex:   hexstr(nks.KeyID),
		SigHex:     hexstr(nks.Signature),
		CBORHex:    hexstr(full),
		SigHashHex: hexstr(sh[:]),
	}
	if len(nks.WrappingPubkey) > 0 {
		g.WrapHex = hexstr(nks.WrappingPubkey)
	}
	return g
}

func main() {
	// Fixed, deterministic byte fields (NOT real keys — we only test serialization/hash).
	pubkey := make([]byte, 32)
	for i := range pubkey {
		pubkey[i] = byte(0xA0 + i)
	}
	keyID := make([]byte, 32)
	for i := range keyID {
		keyID[i] = byte(i)
	}
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(0xF0 ^ i)
	}
	wrap := make([]byte, 32)
	for i := range wrap {
		wrap[i] = byte(0x10 + i)
	}

	// Reference a couple of types so the dependency graph is honest about what we use.
	var _ key.NLPublic
	var _ tkatype.MarshaledSignature

	out := []golden{}

	// 1) A Direct signature.
	out = append(out, dump("direct: kind=1, pubkey+keyID+sig", tka.NodeKeySignature{
		SigKind:   tka.SigDirect,
		Pubkey:    append([]byte(nil), pubkey...),
		KeyID:     append([]byte(nil), keyID...),
		Signature: append([]byte(nil), sig...),
	}))

	// 2) A Credential signature (kind=3), same fields.
	out = append(out, dump("credential: kind=3", tka.NodeKeySignature{
		SigKind:   tka.SigCredential,
		Pubkey:    append([]byte(nil), pubkey...),
		KeyID:     append([]byte(nil), keyID...),
		Signature: append([]byte(nil), sig...),
	}))

	// 3) A Rotation signature (kind=2) nesting a Direct, with WrappingPubkey set on the nested.
	nested := &tka.NodeKeySignature{
		SigKind:        tka.SigDirect,
		Pubkey:         append([]byte(nil), pubkey...),
		KeyID:          append([]byte(nil), keyID...),
		Signature:      append([]byte(nil), sig...),
		WrappingPubkey: append([]byte(nil), wrap...),
	}
	rotSig := make([]byte, 64)
	for i := range rotSig {
		rotSig[i] = byte(0x55 + i)
	}
	out = append(out, dump("rotation: kind=2 nesting direct", tka.NodeKeySignature{
		SigKind:   tka.SigRotation,
		Pubkey:    append([]byte(nil), wrap...), // rotation signs the new (wrap) key
		Signature: append([]byte(nil), rotSig...),
		Nested:    nested,
	}))

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
	_ = fmt.Sprint
}
