use serde::{Deserialize, Serialize};

/// Contains information about a TPM 2.0 device present on a Tailscale node. All fields are read
/// from the TPM device's `TPM_CAP_TPM_PROPERTIES` capability.
///
/// Every field mirrors Go's `tailcfg.TPMInfo`, whose fields are all tagged `json:",omitzero"` —
/// any field may be absent on the wire when it holds its zero value. The container
/// `#[serde(default)]` therefore fills an omitted field with its zero value (rather than failing
/// the decode and dropping the whole `HostInfo`/peer), and `skip_serializing_if` mirrors `omitzero`
/// on the encode side.
///
/// See: Part 2, Section 6.13 of the
/// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct TpmInfo<'a> {
    /// A 4-letter code representing the manufacturer of the TPM device; for example, "MSFT" for
    /// Microsoft. Read from the TPM device's `TPM_PT_MANUFACTURER` property tag.
    ///
    /// Go's `tailcfg.TPMInfo.Manufacturer` is a `string`, marshaled as a bare JSON string (e.g.
    /// `"MSFT"`), so this is a borrowed `&str` to match the wire form — not a JSON array of
    /// characters.
    ///
    /// See: Section 4.1 of the
    /// [TPM Vendor ID registry](https://trustedcomputinggroup.org/resource/vendor-id-registry/).
    #[serde(borrow, skip_serializing_if = "crate::util::is_default")]
    pub manufacturer: &'a str,
    /// A free-form vendor ID string, up to 16 characters. Read from the four
    /// `TPM_PT_VENDOR_STRING_{1-4}` property tags on the TPM device; each property tag contains
    /// 4 of the 16 possible characters.
    ///
    /// See: Part 2, Section 6.13 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(borrow, skip_serializing_if = "crate::util::is_default")]
    pub vendor: &'a str,
    /// A vendor-defined TPM model number. Read from the TPM device's `TPM_PT_VENDOR_TPM_TYPE`
    /// property tag.
    ///
    /// Go's `tailcfg.TPMInfo.Model` is an `int` (marshaled as a bare JSON number), so this is an
    /// `i64` to match the wire form — decoding it as a string would fail and drop the whole peer.
    ///
    /// See: Part 2, Section 6.13 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub model: i64,
    /// A vendor-defined version number for the TPM firmware. Read from the two
    /// `TPM_PT_FIRMWARE_VERSION_{1,2}` property tags on the TPM device.
    ///
    /// Go's `tailcfg.TPMInfo.FirmwareVersion` is a `uint64` (marshaled as a bare JSON number), so
    /// this is a `u64` to match the wire form — decoding it as a string would fail and drop the
    /// whole peer.
    ///
    /// For info on this value and time attestation, see Part 2, Section 10.12.2 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    ///
    /// For info on this value and general data attestation, see Part 2, Section 10.12.12 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub firmware_version: u64,
    /// The TPM 2.0 spec revision encoded as a single number. Before revision 184, TCG used the
    /// "01.83" format for revision 183; as of revision 184 and later, the revision is represented
    /// as an unsigned integer, e.g. `184`.
    ///
    /// Go's `tailcfg.TPMInfo.SpecRevision` is an `int` (like `Model`), so this is an `i64` to match
    /// the wire form — a strictly-unsigned type would fail to decode (and drop the peer) on any
    /// value Go's `int` permits.
    ///
    /// All revisions can be found at <https://trustedcomputinggroup.org/resource/tpm-library-specification/>.
    /// For a discussion of how `TPM_SPEC_VERSION` has changed, see: Part 2, Section 6.1 of the
    /// [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/).
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub spec_revision: i64,
    /// The TPM family indicator, a free-form string (e.g. `"2.0"`). Mirrors Go's
    /// `tailcfg.TPMInfo.FamilyIndicator` (`string`, `omitzero`).
    #[serde(borrow, skip_serializing_if = "crate::util::is_default")]
    pub family_indicator: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-populated `TPMInfo` matching the Go v1.100.0 wire shape: `Manufacturer`/`Vendor`/
    /// `FamilyIndicator` are bare strings, `Model`/`SpecRevision` are bare numbers (Go `int`), and
    /// `FirmwareVersion` is a bare number (Go `uint64`). Previously `Manufacturer` expected a
    /// 4-element char array and `Model`/`FirmwareVersion` expected strings — each wrong type failed
    /// the whole `TpmInfo` → `HostInfo` decode and dropped any TPM-bearing peer.
    #[test]
    fn decodes_go_wire_shape() {
        const TEST: &str = r#"{
            "Manufacturer": "MSFT",
            "Vendor": "vendor-id",
            "Model": 5,
            "FirmwareVersion": 18446744073709551615,
            "SpecRevision": 184,
            "FamilyIndicator": "2.0"
        }"#;

        let tpm: TpmInfo = serde_json::from_str(TEST).unwrap();
        assert_eq!(tpm.manufacturer, "MSFT");
        assert_eq!(tpm.vendor, "vendor-id");
        assert_eq!(tpm.model, 5);
        // u64::MAX — proves FirmwareVersion is a full uint64, not a string or i64.
        assert_eq!(tpm.firmware_version, u64::MAX);
        assert_eq!(tpm.spec_revision, 184);
        assert_eq!(tpm.family_indicator, "2.0");
    }

    /// Every Go field is `json:",omitzero"`, so a real TPM that holds a zero value for some
    /// property omits that field on the wire. The container `#[serde(default)]` must fill the
    /// omitted fields rather than failing the decode (which would drop the peer). Here only
    /// `Manufacturer` is present.
    #[test]
    fn decodes_sparse_omitzero_fields() {
        const TEST: &str = r#"{ "Manufacturer": "MSFT" }"#;
        let tpm: TpmInfo = serde_json::from_str(TEST).unwrap();
        assert_eq!(tpm.manufacturer, "MSFT");
        assert_eq!(tpm.vendor, "");
        assert_eq!(tpm.model, 0);
        assert_eq!(tpm.firmware_version, 0);
        assert_eq!(tpm.spec_revision, 0);
        assert_eq!(tpm.family_indicator, "");
        // An entirely empty object also decodes (all fields omitted).
        assert_eq!(
            serde_json::from_str::<TpmInfo>("{}").unwrap(),
            TpmInfo::default()
        );
    }

    /// The legacy `Manufacturer` JSON-array form (`["M","S","F","T"]`) is no longer accepted: the
    /// field is a string, not a sequence.
    #[test]
    fn manufacturer_rejects_legacy_char_array() {
        const TEST: &str = r#"{ "Manufacturer": ["M", "S", "F", "T"] }"#;
        assert!(serde_json::from_str::<TpmInfo>(TEST).is_err());
    }

    /// `Model`/`FirmwareVersion` as JSON strings (the previous wrong shape) are now rejected — they
    /// must be bare numbers.
    #[test]
    fn numeric_fields_reject_string_form() {
        assert!(serde_json::from_str::<TpmInfo>(r#"{ "Model": "5" }"#).is_err());
        assert!(serde_json::from_str::<TpmInfo>(r#"{ "FirmwareVersion": "1.2.3" }"#).is_err());
    }

    /// A populated `TPMInfo` round-trips, and zero-valued (`omitzero`) fields are skipped on
    /// serialize, mirroring Go's `json:",omitzero"`.
    #[test]
    fn round_trips_and_skips_zero_fields() {
        let tpm = TpmInfo {
            manufacturer: "MSFT",
            vendor: "vendor-id",
            model: 5,
            firmware_version: 42,
            spec_revision: 184,
            family_indicator: "",
        };
        let json = serde_json::to_value(&tpm).unwrap();
        assert_eq!(
            json.get("Manufacturer").and_then(serde_json::Value::as_str),
            Some("MSFT")
        );
        assert_eq!(
            json.get("Model").and_then(serde_json::Value::as_i64),
            Some(5)
        );
        assert_eq!(
            json.get("FirmwareVersion")
                .and_then(serde_json::Value::as_u64),
            Some(42)
        );
        // Zero-valued FamilyIndicator is omitted (omitzero).
        assert!(json.get("FamilyIndicator").is_none());
        // And it decodes back to the same value. `TpmInfo` borrows (`&'a str` fields), so it is
        // not `DeserializeOwned` — round-trip through a `String` and borrow from it via `from_str`
        // (not `from_value`, which requires owned data).
        let serialized = serde_json::to_string(&tpm).unwrap();
        let back: TpmInfo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(back, tpm);
    }
}
