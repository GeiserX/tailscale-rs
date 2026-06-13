package main

// Emits two TKA goldens, both straight from the REAL tailscale.com/tka package
// (pinned tailscale v1.100.0):
//
//   1. NodeKeySignature: the exact CBOR Serialize() + BLAKE2s-256 SigHash() for fixed
//      NodeKeySignature shapes. Printed to STDOUT as a JSON array (so the existing
//      `go run ./tka > ../tka_cbor_sighash_golden.json` regen contract is unchanged). The
//      Rust ts_tka encoder + sig_hash() must reproduce these bytes, or the CTAP2-CBOR
//      ordering / nonempty-bytes / SigHash-preimage logic diverges from Go on the wire.
//      (Backs ts_tka `tka_cbor_matches_go_golden`.)
//
//   2. AUM: for one AUM per MessageKind (AddKey / RemoveKey / UpdateKey / Checkpoint, plus a
//      signed AUM and a populated-State checkpoint), the exact AUM.Serialize() (hex),
//      AUM.Hash() (hex — BLAKE2s-256 of the full serialization INCLUDING signatures) and
//      AUM.SigHash() (hex — BLAKE2s-256 of the serialization with Signatures nil'd). This is
//      the Hash/SigHash cross-vector the literal-only
//      `aum_serialize_matches_go_test_serialization_vectors` test could not provide (those
//      literals are Go's Serialize() bytes, but no Go-produced AUM.Hash() was pinned).
//      Written to the SIBLING file ../tka_aum_hash_golden.json (NOT stdout) so it does not
//      disturb the single-array stdout contract above. (Backs ts_tka
//      `aum_hash_sighash_matches_go_golden`.)

import (
	"encoding/json"
	"os"
	"path/filepath"

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
	Desc       string `json:"desc"`
	SigKind    int    `json:"sig_kind"`
	PubkeyHex  string `json:"pubkey_hex"`
	KeyIDHex   string `json:"key_id_hex"`
	SigHex     string `json:"signature_hex"`
	WrapHex    string `json:"wrapping_pubkey_hex,omitempty"`
	CBORHex    string `json:"cbor_full_hex"` // Serialize(): full CBOR incl. signature
	SigHashHex string `json:"sig_hash_hex"`  // SigHash(): BLAKE2s-256 of CBOR w/ signature nil'd
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

// aumGolden mirrors the AUM half: the serialization plus BOTH digests Go derives from it.
type aumGolden struct {
	Desc         string `json:"desc"`
	MessageKind  int    `json:"message_kind"`
	SerializeHex string `json:"serialize_hex"` // AUM.Serialize(): full CBOR incl. signatures
	HashHex      string `json:"hash_hex"`      // AUM.Hash(): BLAKE2s-256 of Serialize()
	SigHashHex   string `json:"sig_hash_hex"`  // AUM.SigHash(): BLAKE2s-256 of Serialize() w/ Signatures nil
}

func dumpAum(desc string, a tka.AUM) aumGolden {
	ser := a.Serialize() // tkatype.MarshaledAUM ([]byte)
	h := a.Hash()        // AUMHash = [blake2s.Size]byte
	sh := a.SigHash()    // [blake2s.Size]byte
	return aumGolden{
		Desc:         desc,
		MessageKind:  int(a.MessageKind),
		SerializeHex: hexstr(ser),
		HashHex:      hexstr(h[:]),
		SigHashHex:   hexstr(sh[:]),
	}
}

// disablementGolden pins tka.DisablementKDF(secret) — the Argon2i digest stored as a
// DisablementValue in a genesis Checkpoint and matched by Authority.ValidDisablement(secret). The
// Rust ts_tka disablement_value() (for tka_init) MUST reproduce this byte-for-byte, or a lock it
// creates can never be disabled. NOTE: this is Argon2i (x/crypto argon2.Key), NOT BLAKE2s — the
// salt + cost params live inside DisablementKDF (tka/state.go), so we only feed the secret.
type disablementGolden struct {
	Desc      string `json:"desc"`
	SecretHex string `json:"secret_hex"`
	ValueHex  string `json:"value_hex"` // DisablementKDF(secret): the 32-byte Argon2i digest
}

func disablementGoldens() []disablementGolden {
	mk := func(b byte) []byte {
		s := make([]byte, 32)
		for i := range s {
			s[i] = b
		}
		return s
	}
	cases := []struct {
		desc   string
		secret []byte
	}{
		{"all-0xA5 (the tka-package test-helper secret)", mk(0xA5)},
		{"all-zero 32B secret", make([]byte, 32)},
		{"all-0xFF 32B secret", mk(0xFF)},
		{"short secret (5 bytes, KDF accepts any length)", []byte("hello")},
	}
	out := make([]disablementGolden, 0, len(cases))
	for _, c := range cases {
		out = append(out, disablementGolden{
			Desc:      c.desc,
			SecretHex: hexstr(c.secret),
			ValueHex:  hexstr(tka.DisablementKDF(c.secret)),
		})
	}
	return out
}

func nodeKeySignatureGoldens() []golden {
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
	out = append(out, dump("direct: kind=1, pubkey+keyID+sig", tka.NodeKeySignature{
		SigKind:   tka.SigDirect,
		Pubkey:    append([]byte(nil), pubkey...),
		KeyID:     append([]byte(nil), keyID...),
		Signature: append([]byte(nil), sig...),
	}))
	out = append(out, dump("credential: kind=3", tka.NodeKeySignature{
		SigKind:   tka.SigCredential,
		Pubkey:    append([]byte(nil), pubkey...),
		KeyID:     append([]byte(nil), keyID...),
		Signature: append([]byte(nil), sig...),
	}))
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
		Pubkey:    append([]byte(nil), wrap...),
		Signature: append([]byte(nil), rotSig...),
		Nested:    nested,
	}))
	return out
}

func aumGoldens() []aumGolden {
	// Distinct, deterministic byte material (NOT real keys/signatures — serialization+digest oracle).
	prevHash := make([]byte, 32)
	for i := range prevHash {
		prevHash[i] = byte(0x20 + i)
	}
	keyPub := make([]byte, 32)
	for i := range keyPub {
		keyPub[i] = byte(0x40 + i)
	}
	keyPub2 := make([]byte, 32)
	for i := range keyPub2 {
		keyPub2[i] = byte(0x60 + i)
	}
	sigBytes := make([]byte, 64)
	for i := range sigBytes {
		sigBytes[i] = byte(0x80 + i)
	}
	mkPrev := func(b []byte) tka.PrevAUMHash { return tka.PrevAUMHash(append([]byte(nil), b...)) }
	votes2 := uint(2)
	votes7 := uint(7)

	aums := []aumGolden{}

	// (a) AddKey genesis (nil prev) with a real Key25519 + meta.
	aums = append(aums, dumpAum("addkey: genesis, Key25519 votes=7 meta", tka.AUM{
		MessageKind: tka.AUMAddKey,
		Key:         &tka.Key{Kind: tka.Key25519, Votes: votes7, Public: append([]byte(nil), keyPub...), Meta: map[string]string{"name": "alpha"}},
	}))
	// (b) RemoveKey with a non-nil prev (mid-chain link).
	aums = append(aums, dumpAum("removekey: prev set, KeyID", tka.AUM{
		MessageKind: tka.AUMRemoveKey,
		PrevAUMHash: mkPrev(prevHash),
		KeyID:       append([]byte(nil), keyPub...),
	}))
	// (c) UpdateKey with votes + meta.
	aums = append(aums, dumpAum("updatekey: votes=2 + meta", tka.AUM{
		MessageKind: tka.AUMUpdateKey,
		PrevAUMHash: mkPrev(prevHash),
		KeyID:       append([]byte(nil), keyPub...),
		Votes:       &votes2,
		Meta:        map[string]string{"role": "ci"},
	}))
	// (d) Checkpoint carrying a State whose DisablementValues is NIL (Go zero value). Go encodes a
	// nil non-omitempty slice as CBOR null (0xf6); a populated one as an array — see case (f).
	var lastHash tka.AUMHash
	copy(lastHash[:], prevHash)
	aums = append(aums, dumpAum("checkpoint: State w/ nil DisablementValues, 2 keys", tka.AUM{
		MessageKind: tka.AUMCheckpoint,
		PrevAUMHash: mkPrev(prevHash),
		State: &tka.State{
			LastAUMHash: &lastHash,
			Keys: []tka.Key{
				{Kind: tka.Key25519, Votes: 1, Public: append([]byte(nil), keyPub...)},
				{Kind: tka.Key25519, Votes: 3, Public: append([]byte(nil), keyPub2...), Meta: map[string]string{"k": "v"}},
			},
		},
	}))
	// (e) AddKey carrying Signatures (key 23): proves Hash (incl sigs) != SigHash (excl).
	aums = append(aums, dumpAum("addkey: with 1 signature", tka.AUM{
		MessageKind: tka.AUMAddKey,
		PrevAUMHash: mkPrev(prevHash),
		Key:         &tka.Key{Kind: tka.Key25519, Votes: 1, Public: append([]byte(nil), keyPub...)},
		Signatures: []tkatype.Signature{
			{KeyID: append([]byte(nil), keyPub2...), Signature: append([]byte(nil), sigBytes...)},
		},
	}))
	// (f) Checkpoint carrying a State with a POPULATED DisablementValues (the common real shape).
	aums = append(aums, dumpAum("checkpoint: State w/ populated DisablementValues, 1 key", tka.AUM{
		MessageKind: tka.AUMCheckpoint,
		PrevAUMHash: mkPrev(prevHash),
		State: &tka.State{
			LastAUMHash:       &lastHash,
			DisablementValues: [][]byte{{0xaa, 0xbb}},
			Keys:              []tka.Key{{Kind: tka.Key25519, Votes: 1, Public: append([]byte(nil), keyPub...)}},
		},
	}))
	return aums
}

func main() {
	// Block 1 -> stdout (preserves the existing single-array regen contract).
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(nodeKeySignatureGoldens()); err != nil {
		panic(err)
	}

	// Block 2 -> sibling JSON file tests/vectors/tka_aum_hash_golden.json.
	// __file__ is tests/vectors/gen/tka/main.go; the vectors dir is three levels up.
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	// `go run ./tka` runs with CWD = tests/vectors/gen, so the vectors dir is the parent.
	// `go run ./tka` runs with CWD = tests/vectors/gen (per VENDOR.md), so the vectors dir is
	// the parent. The generator is only ever invoked that way.
	outPath := filepath.Join(wd, "..", "tka_aum_hash_golden.json")
	f, err := os.Create(outPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fe := json.NewEncoder(f)
	fe.SetIndent("", "  ")
	if err := fe.Encode(aumGoldens()); err != nil {
		panic(err)
	}

	// Block 3 -> sibling JSON file tests/vectors/tka_disablement_golden.json: the Argon2i
	// DisablementKDF goldens (backs ts_tka `disablement_value_matches_go_golden`).
	dPath := filepath.Join(wd, "..", "tka_disablement_golden.json")
	df, err := os.Create(dPath)
	if err != nil {
		panic(err)
	}
	defer df.Close()
	dfe := json.NewEncoder(df)
	dfe.SetIndent("", "  ")
	if err := dfe.Encode(disablementGoldens()); err != nil {
		panic(err)
	}
}
