#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::IdentityError;

/// Reads an ASN.1 DER tag, header length, and value length from a byte slice.
fn read_tlv(input: &[u8]) -> Result<(u8, usize, usize), IdentityError> {
    if input.is_empty() {
        return Err(IdentityError::InvalidKey(
            "unexpected end of ASN.1 buffer".into(),
        ));
    }
    let tag = input[0];
    if input.len() < 2 {
        return Err(IdentityError::InvalidKey(
            "truncated ASN.1 TLV header".into(),
        ));
    }
    let second = input[1];
    let (header_len, val_len) = if second < 0x80 {
        (2usize, usize::from(second))
    } else {
        let count = usize::from(second & 0x7f);
        if count == 0 || count > 4 || input.len() < 2 + count {
            return Err(IdentityError::InvalidKey(
                "invalid ASN.1 multi-byte length".into(),
            ));
        }
        let mut len = 0usize;
        for &b in &input[2..2 + count] {
            len = (len << 8) | usize::from(b);
        }
        (2 + count, len)
    };
    if input.len() < header_len + val_len {
        return Err(IdentityError::InvalidKey(
            "ASN.1 length exceeds available bytes".into(),
        ));
    }
    Ok((tag, header_len, val_len))
}

/// Extracts the complete DER-encoded `SubjectPublicKeyInfo` structure from an `X.509` certificate `DER`.
///
/// # Errors
///
/// Returns an [`IdentityError::InvalidKey`] if the certificate ASN.1 structure cannot be traversed.
pub fn extract_spki(cert_der: &[u8]) -> Result<&[u8], IdentityError> {
    let (outer_tag, outer_hdr, outer_val) = read_tlv(cert_der)?;
    if outer_tag != 0x30 {
        return Err(IdentityError::InvalidKey(
            "outer tag is not SEQUENCE".into(),
        ));
    }
    let cert_body = &cert_der[outer_hdr..outer_hdr + outer_val];

    let (tbs_tag, tbs_hdr, tbs_val) = read_tlv(cert_body)?;
    if tbs_tag != 0x30 {
        return Err(IdentityError::InvalidKey(
            "TBSCertificate tag is not SEQUENCE".into(),
        ));
    }
    let mut cursor = &cert_body[tbs_hdr..tbs_hdr + tbs_val];

    let (tag, h_len, v_len) = read_tlv(cursor)?;
    if tag == 0xa0 {
        cursor = &cursor[h_len + v_len..];
    }

    for _ in 0..5 {
        let (_, h, v) = read_tlv(cursor)?;
        cursor = &cursor[h + v..];
    }

    let (spki_tag, spki_h, spki_v) = read_tlv(cursor)?;
    if spki_tag != 0x30 {
        return Err(IdentityError::InvalidKey(
            "SubjectPublicKeyInfo tag is not SEQUENCE".into(),
        ));
    }
    let total_spki_len = spki_h + spki_v;
    Ok(&cursor[..total_spki_len])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};

    #[test]
    fn spki_matches_keypair_public_key() {
        let key_pair = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let params = CertificateParams::new(vec!["test".into()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let extracted_spki = extract_spki(cert.der()).unwrap();
        let expected_spki = key_pair.public_key_der();
        assert_eq!(extracted_spki, expected_spki.as_slice());
    }
}
