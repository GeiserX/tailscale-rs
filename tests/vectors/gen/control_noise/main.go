package main

// Control-plane Noise_IK transcript cross-KAT reference generator for ts_control_noise.
//
// ts_control_noise's `Handshake::initialize` drives a `noise_protocol` IK handshake over
// <X25519, ChaCha20Poly1305BigEndian, Blake2s> (noise-rust-crypto) — the exact construction
// Tailscale's `control/controlbase` uses on the wire: protocol name
// "Noise_IK_25519_ChaChaPoly_BLAKE2s", both handshake payloads EMPTY, and the client
// (initiator) takes tx = c1 (i->r) / rx = c2 (r->i) from Split().
//
// Only the AEAD leaf (the big-endian transport nonce) is currently Go-pinned
// (`be_aead_matches_go_kat` in cipher.rs). The IK TRANSCRIPT itself — the DH schedule, the
// MixHash/MixKey ordering, prologue absorption, and the Split -> (tx, rx) direction — is NOT.
// A divergence there would let two Rust nodes interoperate while silently failing against
// every Go control server (a total registration break invisible to a self-round-trip test).
//
// This generator is an INDEPENDENT Go Noise implementation (flynn/noise v1.1.0) driven with
// FIXED static + ephemeral keypairs so msg1/msg2 and the split ciphers are deterministic. The
// Rust KAT reproduces the same bytes through the real production builder path with a test-only
// fixed-ephemeral seam (builder.set_e).
//
// NB on the ephemeral seam: flynn/noise's write path does NOT honor Config.EphemeralKeypair —
// it calls GenerateKeypair(Config.Random) and overwrites the ephemeral (state.go WriteMessage,
// MessagePatternE). The real injection seam is therefore Config.Random: a deterministic reader
// that yields exactly the 32 fixed private-scalar bytes makes GenerateKeypair derive the fixed
// keypair (it does io.ReadFull(rng, priv[:32]); pub = X25519(priv, Basepoint) — identical to
// noise-rust-crypto). Each party writes its `e` token exactly once, so a 32-byte reader suffices.
//
// The KAT pins the transcript MECHANICS with a FIXED prologue constant (below). That is
// deliberately independent of the production CapabilityVersion::CURRENT wiring — the prologue
// string is whatever the caller passes to `Handshake::initialize`; here we hardcode one fixed
// value in BOTH this generator and the Rust test so the transcript is reproducible.
//
// flynn/noise is pinned via the gen go.mod (github.com/flynn/noise v1.1.0); the DH/Cipher/Hash
// primitives come from golang.org/x/crypto v0.52.0.

import (
	"bytes"
	"encoding/json"
	"os"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// fixedPrologue pins the transcript mechanics. It MUST match the Rust KAT byte-for-byte. This
// is NOT the production CapabilityVersion::CURRENT prologue — it is a fixed test constant.
const fixedPrologue = "Tailscale Control Protocol v109"

// probePlaintext is sealed under each split cipher at counter 0 to pin the split ciphers
// behaviorally (flynn/noise CipherState key bytes are unexported). counter 0 is identical
// under little-endian (flynn/noise) and big-endian (the fork's transport AEAD) nonce packing,
// so this is a valid cross-implementation check of the split-key DERIVATION and DIRECTION.
const probePlaintext = "control-noise-probe"

func hexstr(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = h[c>>4]
		out[i*2+1] = h[c&0xf]
	}
	return string(out)
}

// pubOf derives the X25519 public key for a private scalar over the curve basepoint, exactly
// as noise-rust-crypto does (StaticSecret::from(priv); PublicKey::from(&secret)). curve25519
// clamps the scalar internally, matching x25519-dalek.
func pubOf(priv []byte) []byte {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return pub
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

type transcript struct {
	Desc          string `json:"desc"`
	ProtocolName  string `json:"protocol_name"`
	PrologueAscii string `json:"prologue_ascii"`
	PrologueHex   string `json:"prologue_hex"`

	// Fixed inputs.
	InitStaticPrivHex string `json:"init_static_priv_hex"`
	InitStaticPubHex  string `json:"init_static_pub_hex"`
	RespStaticPrivHex string `json:"resp_static_priv_hex"`
	RespStaticPubHex  string `json:"resp_static_pub_hex"`
	InitEphemPrivHex  string `json:"init_ephem_priv_hex"`
	InitEphemPubHex   string `json:"init_ephem_pub_hex"`
	RespEphemPrivHex  string `json:"resp_ephem_priv_hex"`
	RespEphemPubHex   string `json:"resp_ephem_pub_hex"`

	// Wire messages (Noise bodies; empty payloads).
	Msg1Hex string `json:"msg1_hex"`
	Msg2Hex string `json:"msg2_hex"`

	// Behavioral split-cipher pins. Both probes sealed at counter 0, empty AD.
	ProbeAscii       string `json:"probe_ascii"`
	ProbeHex         string `json:"probe_hex"`
	ProbeAdHex       string `json:"probe_ad_hex"`
	TxProbeSealedHex string `json:"tx_probe_sealed_hex"` // csI0 = initiator send = i->r = tx
	RxProbeSealedHex string `json:"rx_probe_sealed_hex"` // csI1 = initiator recv = r->i = rx

	// Optional: the IK handshake hash (flynn/noise ChannelBinding).
	HandshakeHashHex string `json:"handshake_hash_hex"`
}

func main() {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

	initStaticPriv := bytes32(0x01)
	respStaticPriv := bytes32(0x02)
	initEphemPriv := bytes32(0x03)
	respEphemPriv := bytes32(0x04)

	initStaticPub := pubOf(initStaticPriv)
	respStaticPub := pubOf(respStaticPriv)
	initEphemPub := pubOf(initEphemPriv)
	respEphemPub := pubOf(respEphemPriv)

	initStatic := noise.DHKey{Private: initStaticPriv, Public: initStaticPub}
	respStatic := noise.DHKey{Private: respStaticPriv, Public: respStaticPub}
	initEphem := noise.DHKey{Private: initEphemPriv, Public: initEphemPub}
	respEphem := noise.DHKey{Private: respEphemPriv, Public: respEphemPub}

	prologue := []byte(fixedPrologue)

	// Initiator: IK, fixed static, peer static = responder static. The fixed ephemeral is
	// injected via Random (see note above): GenerateKeypair reads the 32 init-ephemeral bytes.
	initiator, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:      cs,
		Pattern:          noise.HandshakeIK,
		Initiator:        true,
		Prologue:         prologue,
		StaticKeypair:    initStatic,
		EphemeralKeypair: initEphem,
		PeerStatic:       respStaticPub,
		Random:           bytes.NewReader(initEphemPriv),
	})
	if err != nil {
		panic(err)
	}

	// Responder: IK, fixed static + fixed ephemeral. In IK the responder does NOT pre-know the
	// initiator's static — it learns it from the encrypted `s` token inside msg1 (that is the
	// whole point of IK's initiator-identity-hiding). Setting PeerStatic here is rejected by
	// flynn/noise ("rs is not nil"). The Rust production initiator path is unaffected: it
	// correctly pre-sets only the RESPONDER static via set_rs (which an IK initiator must know).
	responder, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:      cs,
		Pattern:          noise.HandshakeIK,
		Initiator:        false,
		Prologue:         prologue,
		StaticKeypair:    respStatic,
		EphemeralKeypair: respEphem,
		Random:           bytes.NewReader(respEphemPriv),
	})
	if err != nil {
		panic(err)
	}

	// msg1: initiator -> responder, EMPTY payload.
	msg1, _, _, err := initiator.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}

	// Responder reads msg1 (no split yet on the first IK message), EMPTY payload expected.
	rd, _, _, err := responder.ReadMessage(nil, msg1)
	if err != nil {
		panic(err)
	}
	if len(rd) != 0 {
		panic("responder read non-empty msg1 payload")
	}

	// msg2: responder -> initiator, EMPTY payload. This completes the responder and splits.
	msg2, csR0, csR1, err := responder.WriteMessage(nil, nil)
	if err != nil {
		panic(err)
	}
	if csR0 == nil || csR1 == nil {
		panic("responder did not split on msg2")
	}

	// Initiator reads msg2, completes, and splits. EMPTY payload expected.
	rd2, csI0, csI1, err := initiator.ReadMessage(nil, msg2)
	if err != nil {
		panic(err)
	}
	if len(rd2) != 0 {
		panic("initiator read non-empty msg2 payload")
	}
	if csI0 == nil || csI1 == nil {
		panic("initiator did not split on msg2")
	}

	// Cross-check the two parties' channel binding hashes agree (the handshake transcript
	// matched end-to-end) before emitting.
	if hexstr(initiator.ChannelBinding()) != hexstr(responder.ChannelBinding()) {
		panic("initiator/responder channel binding mismatch")
	}

	// Behavioral split-cipher pins. Noise spec Split() returns (c1, c2) where c1 is the
	// initiator->responder cipher and c2 the responder->initiator cipher, on BOTH sides. So
	// the initiator's csI0 is i->r (tx) and csI1 is r->i (rx). Seal the probe at counter 0.
	probe := []byte(probePlaintext)
	txSealed, err := csI0.Encrypt(nil, nil, probe) // i->r
	if err != nil {
		panic(err)
	}
	rxSealed, err := csI1.Encrypt(nil, nil, probe) // r->i
	if err != nil {
		panic(err)
	}

	// Sanity: the responder's mirrored ciphers decrypt them (csR0 opens i->r, csR1 opens
	// r->i), confirming the direction labeling before we pin it.
	if _, err := csR0.Decrypt(nil, nil, txSealed); err != nil {
		panic("responder c1 (i->r) failed to open initiator tx probe: " + err.Error())
	}
	if _, err := csR1.Decrypt(nil, nil, rxSealed); err != nil {
		panic("responder c2 (r->i) failed to open initiator rx probe: " + err.Error())
	}

	out := transcript{
		Desc:          "Noise_IK control transcript, fixed statics/ephemerals, empty payloads, fixed prologue",
		ProtocolName:  "Noise_IK_25519_ChaChaPoly_BLAKE2s",
		PrologueAscii: fixedPrologue,
		PrologueHex:   hexstr(prologue),

		InitStaticPrivHex: hexstr(initStaticPriv),
		InitStaticPubHex:  hexstr(initStaticPub),
		RespStaticPrivHex: hexstr(respStaticPriv),
		RespStaticPubHex:  hexstr(respStaticPub),
		InitEphemPrivHex:  hexstr(initEphemPriv),
		InitEphemPubHex:   hexstr(initEphemPub),
		RespEphemPrivHex:  hexstr(respEphemPriv),
		RespEphemPubHex:   hexstr(respEphemPub),

		Msg1Hex: hexstr(msg1),
		Msg2Hex: hexstr(msg2),

		ProbeAscii:       probePlaintext,
		ProbeHex:         hexstr(probe),
		ProbeAdHex:       "",
		TxProbeSealedHex: hexstr(txSealed),
		RxProbeSealedHex: hexstr(rxSealed),

		HandshakeHashHex: hexstr(initiator.ChannelBinding()),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
