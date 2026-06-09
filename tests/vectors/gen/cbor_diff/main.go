package main

// Differential-oracle half for fuzzing the Rust ts_tka CBOR decoder.
//
// Reads a CBOR blob from stdin (the SAME bytes a Tailnet-Lock peer would present as a node-key
// signature) and reports whether Go's `github.com/fxamacker/cbor/v2` — the library upstream
// Tailscale `tka` uses — accepts or rejects it, plus the decoded shape. The intent is differential
// fuzzing: feed an identical corpus to both decoders (Rust `ts_tka` via the cargo-fuzz target
// `ts_tka/fuzz/fuzz_targets/cbor_decode.rs`, and this Go oracle) and assert they agree on
// accept/reject. See this directory's README for how the two halves fit together (follow-on:
// tsr-19k).
//
// Output is a single JSON object on stdout:
//
//	{"len":N,"accepted":bool,"error":"...","shape":<decoded-or-null>}
//
// `accepted` is the load-bearing field for the differential assertion; `shape` is advisory (it lets
// a human eyeball what Go decoded). We decode with the SAME CTAP2-canonical decode posture the TKA
// wire format relies on: definite lengths, no duplicate map keys, reject trailing bytes.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// report is the JSON document printed to stdout for one input blob.
type report struct {
	Len      int         `json:"len"`
	Accepted bool        `json:"accepted"`
	Error    string      `json:"error,omitempty"`
	Shape    interface{} `json:"shape"`
}

// strictDecMode mirrors the decode posture the Rust ts_tka decoder enforces (and that fxamacker's
// CTAP2 encoder produces on the other side): definite-length items only and duplicate map keys are
// an error. (Trailing bytes after the top-level item are handled explicitly via UnmarshalFirst's
// `rest` below.) This keeps the two decoders comparable on the same accept/reject criteria rather
// than diverging on lenient defaults.
func strictDecMode() (cbor.DecMode, error) {
	return cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
}

// jsonSafe rewrites a CBOR-decoded value into something `encoding/json` can marshal: maps with
// non-string keys (CBOR int-keyed maps decode to map[interface{}]interface{}) become
// map[string]interface{} with `fmt`-formatted keys, recursively. Byte strings are left as []byte
// (json renders them base64), which is fine for the advisory `shape` field.
func jsonSafe(v interface{}) interface{} {
	switch m := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for k, val := range m {
			out[fmt.Sprintf("%v", k)] = jsonSafe(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(m))
		for i, val := range m {
			out[i] = jsonSafe(val)
		}
		return out
	default:
		return v
	}
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		os.Exit(2)
	}

	dm, err := strictDecMode()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build decode mode:", err)
		os.Exit(2)
	}

	rep := report{Len: len(data)}

	// Decode into a generic value: a node-key signature is an integer-keyed CBOR map, so the most
	// faithful generic target is map[interface{}]interface{}. We additionally require that the WHOLE
	// input is consumed (no trailing bytes), matching the Rust decoder's "trailing bytes after
	// signature" rejection.
	var shape interface{}
	rest, derr := dm.UnmarshalFirst(data, &shape)
	switch {
	case derr != nil:
		rep.Accepted = false
		rep.Error = derr.Error()
	case len(rest) != 0:
		rep.Accepted = false
		rep.Error = fmt.Sprintf("trailing bytes after top-level item: %d", len(rest))
	default:
		rep.Accepted = true
		// A CBOR int-keyed map decodes into map[interface{}]interface{}, whose non-string keys
		// `encoding/json` cannot marshal. `accepted` (the differential-comparison field) is already
		// set; make the advisory `shape` JSON-safe by stringifying map keys recursively.
		rep.Shape = jsonSafe(shape)
	}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(os.Stderr, "encode report:", err)
		os.Exit(2)
	}
}
