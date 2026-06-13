package main

// WireGuard (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s) reference vectors for ts_tunnel.
//
// Two independent KATs:
//
//   (A) TRANSPORT-DATA NONCE KAT. WireGuard transport frames use ChaCha20Poly1305 with a
//       12-byte nonce = 4 zero bytes || little-endian uint64 counter, empty AAD. This is the
//       LITTLE-endian counterpart of the control-plane BE nonce — ts_tunnel/session.rs builds
//       it via a zerocopy struct {_zero: U32, counter: U64(LE)}. We pin Go's ciphertext+tag.
//
//   (B) HANDSHAKE TRANSCRIPT. A faithful re-implementation of wireguard-go's
//       device/noise-protocol.go construction (same labels, same Mix order, HKDF over BLAKE2s,
//       ChaChaPoly with all-zero handshake nonce) driven with FIXED ephemerals and statics, so
//       the initiation/response payloads and the final split transport keys are deterministic.
//       The Rust ts_tunnel handshake (with a test-only fixed-ephemeral seam) must reproduce the
//       same transport keys byte-for-byte. The construction here is lifted from wireguard-go:
//       https://git.zx2c4.com/wireguard-go/tree/device/noise-protocol.go
//
// Labels (verbatim from WireGuard / wireguard-go):
//   NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
//   WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"hash"
	"os"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// newBlake2s is the hash constructor wireguard-go feeds to crypto/hmac (device/kdf.go).
func newBlake2s() hash.Hash {
	h, _ := blake2s.New256(nil)
	return h
}

const (
	noiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	wgIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
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

func unhex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		out[i] = unhexNib(s[i*2])<<4 | unhexNib(s[i*2+1])
	}
	return out
}

// ---- BLAKE2s helpers (wireguard-go uses 256-bit blake2s for HASH and HMAC base) ----

func blakeHash(in ...[]byte) [blake2s.Size]byte {
	h, _ := blake2s.New256(nil)
	for _, b := range in {
		h.Write(b)
	}
	var out [blake2s.Size]byte
	h.Sum(out[:0])
	return out
}

func mixHash(h [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	return blakeHash(h[:], data)
}

// HMAC-BLAKE2s (NOT keyed-blake2s) — this is what wireguard-go's KDFn and Rust's
// SimpleHkdf<Blake2s256> both use. Using keyed-blake2s here silently diverges.
func hmac1(key, in0 []byte) [blake2s.Size]byte {
	mac := hmac.New(newBlake2s, key)
	mac.Write(in0)
	var out [blake2s.Size]byte
	mac.Sum(out[:0])
	return out
}

func hmac2(key, in0, in1 []byte) [blake2s.Size]byte {
	mac := hmac.New(newBlake2s, key)
	mac.Write(in0)
	mac.Write(in1)
	var out [blake2s.Size]byte
	mac.Sum(out[:0])
	return out
}

// KDF1/KDF2/KDF3 as in wireguard-go device/kdf.go.
func kdf1(key, input []byte) [blake2s.Size]byte {
	prk := hmac1(key, input)
	t0 := hmac1(prk[:], []byte{0x1})
	return t0
}

func kdf2(key, input []byte) ([blake2s.Size]byte, [blake2s.Size]byte) {
	prk := hmac1(key, input)
	t0 := hmac1(prk[:], []byte{0x1})
	t1 := hmac2(prk[:], t0[:], []byte{0x2})
	return t0, t1
}

func kdf3(key, input []byte) ([blake2s.Size]byte, [blake2s.Size]byte, [blake2s.Size]byte) {
	prk := hmac1(key, input)
	t0 := hmac1(prk[:], []byte{0x1})
	t1 := hmac2(prk[:], t0[:], []byte{0x2})
	t2 := hmac2(prk[:], t1[:], []byte{0x3})
	return t0, t1, t2
}

func dh(priv, pub []byte) []byte {
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		panic(err)
	}
	return out
}

func pubOf(priv []byte) []byte {
	out, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return out
}

func aeadSeal(key [blake2s.Size]byte, counter uint64, plaintext, ad []byte) []byte {
	aead, _ := chacha20poly1305.New(key[:])
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return aead.Seal(nil, nonce[:], plaintext, ad)
}

type out struct {
	TransportNonce []transportVec `json:"transport_nonce_kat"`
	Handshake      handshakeVec   `json:"handshake_transcript"`
}

type transportVec struct {
	Desc     string `json:"desc"`
	KeyHex   string `json:"key_hex"`
	Counter  uint64 `json:"counter"`
	NonceHex string `json:"nonce_hex"`
	PtHex    string `json:"pt_hex"`
	CtHex    string `json:"ct_hex"` // ciphertext||tag, empty AAD
}

type handshakeVec struct {
	Desc string `json:"desc"`
	// Fixed inputs:
	InitStaticPrivHex  string `json:"init_static_priv_hex"`
	InitStaticPubHex   string `json:"init_static_pub_hex"`
	RespStaticPrivHex  string `json:"resp_static_priv_hex"`
	RespStaticPubHex   string `json:"resp_static_pub_hex"`
	InitEphemPrivHex   string `json:"init_ephem_priv_hex"`
	RespEphemPrivHex   string `json:"resp_ephem_priv_hex"`
	PskHex             string `json:"psk_hex"`
	TimestampHex       string `json:"timestamp_hex"`
	// Outputs (the wire-critical bytes):
	InitEphemPubHex     string `json:"init_ephem_pub_hex"`
	InitStaticSealedHex string `json:"init_static_sealed_hex"` // encrypted initiator static
	InitTsSealedHex     string `json:"init_ts_sealed_hex"`     // encrypted timestamp payload
	RespEphemPubHex     string `json:"resp_ephem_pub_hex"`
	RespEmptySealedHex  string `json:"resp_empty_sealed_hex"`  // encrypted empty payload (auth tag)
	SendKeyHex          string `json:"send_key_i2r_hex"`       // initiator->responder transport key
	RecvKeyHex          string `json:"recv_key_r2i_hex"`       // responder->initiator transport key

	// Assembled on-wire frames with mac1/mac2 ZEROED (we pin the byte layout + sealed fields; the
	// macs are a separate keyed-hash concern out of scope here). Sender/receiver indices are fixed
	// (set in main) for determinism.
	InitSenderIndex   uint32 `json:"init_sender_index"`     // initiation sender index (little-endian on wire)
	RespSenderIndex   uint32 `json:"resp_sender_index"`     // response sender index
	RespReceiverIndex uint32 `json:"resp_receiver_index"`   // response receiver index (== init sender)
	InitFrameNoMacHex string `json:"init_frame_no_mac_hex"` // HandshakeInitiation bytes through timestamp (116 B, pre-mac)
	RespFrameNoMacHex string `json:"resp_frame_no_mac_hex"` // HandshakeResponse bytes through auth_tag (60 B, pre-mac)
}

func main() {
	// ---- (A) transport-data nonce KAT ----
	tkey := [blake2s.Size]byte{}
	for i := range tkey {
		tkey[i] = byte(0x11 * 1) // 0x11 repeated
		tkey[i] = 0x11
	}
	tn := []transportVec{}
	for _, c := range []struct {
		desc    string
		counter uint64
		pt      string
	}{
		{"counter 0, short pt", 0, "78797a7a79"}, // "xyzzy"
		{"counter 1, short pt", 1, "706c6f766572"},
		{"high counter, fixed pt", 0x0102030405060708, "deadbeef"},
	} {
		var nonce [12]byte
		binary.LittleEndian.PutUint64(nonce[4:], c.counter)
		ct := aeadSeal(tkey, c.counter, unhex(c.pt), nil)
		tn = append(tn, transportVec{
			Desc:     c.desc,
			KeyHex:   hexstr(tkey[:]),
			Counter:  c.counter,
			NonceHex: hexstr(nonce[:]),
			PtHex:    c.pt,
			CtHex:    hexstr(ct),
		})
	}

	// ---- (B) handshake transcript with FIXED keys ----
	// Clamp helper not needed: curve25519.X25519 clamps the scalar internally.
	initStaticPriv := bytes32(0x01)
	respStaticPriv := bytes32(0x02)
	initEphemPriv := bytes32(0x03)
	respEphemPriv := bytes32(0x04)
	psk := bytes32(0x05)
	var timestamp [12]byte // TAI64N; use fixed all-0x07 for determinism
	for i := range timestamp {
		timestamp[i] = 0x07
	}

	initStaticPub := pubOf(initStaticPriv)
	respStaticPub := pubOf(respStaticPriv)
	initEphemPub := pubOf(initEphemPriv)
	respEphemPub := pubOf(respEphemPriv)

	// --- Initiator builds initiation (mirrors ts_tunnel initiate_handshake) ---
	// hash = HASH(NoiseConstruction); chainingKey = hash
	h0 := blakeHash([]byte(noiseConstruction))
	ck := h0
	hsh := mixHash(h0, []byte(wgIdentifier))
	hsh = mixHash(hsh, respStaticPub) // responder static
	// mix_hash(e) ; mix_key(e) (psk variant double-mix on ephemeral)
	hsh = mixHash(hsh, initEphemPub)
	ck = kdf1(ck[:], initEphemPub)
	// mix_key(es): ck,k = kdf2(ck, dh(e_i, s_r))
	ck, k := kdf2(ck[:], dh(initEphemPriv, respStaticPub))
	// encrypt initiator static under k with hash as AAD, handshake counter 0
	initStaticSealed := aeadSeal(k, 0, initStaticPub, hsh[:])
	hsh = mixHash(hsh, initStaticSealed)
	// mix_key(ss)
	ck, k = kdf2(ck[:], dh(initStaticPriv, respStaticPub))
	// encrypt timestamp payload
	initTsSealed := aeadSeal(k, 0, timestamp[:], hsh[:])
	hsh = mixHash(hsh, initTsSealed)

	// --- Responder consumes & responds (mirrors respond) ---
	// mix_hash(e_r) ; mix_key(e_r)
	hsh = mixHash(hsh, respEphemPub)
	ck = kdf1(ck[:], respEphemPub)
	// mix_key(ee) = dh(e_r, e_i)
	ck = kdf1(ck[:], dh(respEphemPriv, initEphemPub))
	// mix_key(se) responder: dh(e_r, s_i)
	ck = kdf1(ck[:], dh(respEphemPriv, initStaticPub))
	// mix_psk: ck,h2,k = kdf3(ck, psk); mix_hash(h2)
	var h2, kpsk [blake2s.Size]byte
	ck, h2, kpsk = kdf3(ck[:], psk)
	hsh = mixHash(hsh, h2[:])
	// encrypt empty payload -> response auth tag
	respEmptySealed := aeadSeal(kpsk, 0, nil, hsh[:])
	hsh = mixHash(hsh, respEmptySealed)
	// split: sendKey (i2r), recvKey (r2i) = kdf2(ck, empty)
	sendKey, recvKey := kdf2(ck[:], nil)

	// --- Assemble the on-wire frames (mac1/mac2 zeroed; layout mirrors ts_tunnel's #[repr(C)]
	// HandshakeInitiation / HandshakeResponse). Indices are little-endian (WireGuard wire format).
	// Fixed indices for determinism: the Rust KAT builds with the same values.
	const initSenderIdx uint32 = 0x11111111
	const respSenderIdx uint32 = 0x22222222
	// HandshakeInitiation: msg_type(1=0x01) + reserved(3×0) + sender_index(4, LE) + ephemeral(32)
	//   + static_pub_sealed(48) + timestamp_sealed(28). 116 bytes, pre-mac.
	var idx4 [4]byte
	initFrame := []byte{0x01, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(idx4[:], initSenderIdx)
	initFrame = append(initFrame, idx4[:]...)
	initFrame = append(initFrame, initEphemPub...)
	initFrame = append(initFrame, initStaticSealed...)
	initFrame = append(initFrame, initTsSealed...)
	// HandshakeResponse: msg_type(2=0x02) + reserved(3) + sender_index(4, LE) + receiver_index(4, LE,
	//   == init sender) + ephemeral(32) + auth_tag(16). 60 bytes, pre-mac.
	respFrame := []byte{0x02, 0x00, 0x00, 0x00}
	binary.LittleEndian.PutUint32(idx4[:], respSenderIdx)
	respFrame = append(respFrame, idx4[:]...)
	binary.LittleEndian.PutUint32(idx4[:], initSenderIdx) // responder's receiver == initiator's sender
	respFrame = append(respFrame, idx4[:]...)
	respFrame = append(respFrame, respEphemPub...)
	respFrame = append(respFrame, respEmptySealed...)

	hv := handshakeVec{
		Desc:                "Noise_IKpsk2 transcript, fixed ephemerals/statics",
		InitStaticPrivHex:   hexstr(initStaticPriv),
		InitStaticPubHex:    hexstr(initStaticPub),
		RespStaticPrivHex:   hexstr(respStaticPriv),
		RespStaticPubHex:    hexstr(respStaticPub),
		InitEphemPrivHex:    hexstr(initEphemPriv),
		RespEphemPrivHex:    hexstr(respEphemPriv),
		PskHex:              hexstr(psk),
		TimestampHex:        hexstr(timestamp[:]),
		InitEphemPubHex:     hexstr(initEphemPub),
		InitStaticSealedHex: hexstr(initStaticSealed),
		InitTsSealedHex:     hexstr(initTsSealed),
		RespEphemPubHex:     hexstr(respEphemPub),
		RespEmptySealedHex:  hexstr(respEmptySealed),
		SendKeyHex:          hexstr(sendKey[:]),
		RecvKeyHex:          hexstr(recvKey[:]),
		InitSenderIndex:     initSenderIdx,
		RespSenderIndex:     respSenderIdx,
		RespReceiverIndex:   initSenderIdx,
		InitFrameNoMacHex:   hexstr(initFrame),
		RespFrameNoMacHex:   hexstr(respFrame),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out{TransportNonce: tn, Handshake: hv}); err != nil {
		panic(err)
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
