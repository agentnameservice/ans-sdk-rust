//! Real-signature tests for the sealed identity boundary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use ans_types::ProvenIdentityKey;
use base64::prelude::BASE64_STANDARD;
use p256::{
    ecdsa::{SigningKey, signature::Signer as _},
    pkcs8::EncodePublicKey as _,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _, RsaKeyPair};
use serde_json::json;
use sha2::{Digest as _, Sha256};

const ID: &str = "0193f0c5-7b2e-7a41-9c3d-aaaaaaaaaaaa";
const DID: &str = "did:web:identity.example.com";
const RA: &str = "https://ra.example.com";

enum Signer {
    Ed(Ed25519KeyPair),
    Ec(SigningKey),
    Rsa(RsaKeyPair),
}
impl Signer {
    fn ed(seed: u8) -> Self {
        Self::Ed(Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap())
    }
    fn ec() -> Self {
        Self::Ec(SigningKey::from_slice(&[7; 32]).unwrap())
    }
    fn rsa() -> Self {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        Self::Rsa(RsaKeyPair::from_pkcs8(&key.serialize_der()).unwrap())
    }
    fn alg(&self) -> &str {
        match self {
            Self::Ed(_) => "EdDSA",
            Self::Ec(_) => "ES256",
            Self::Rsa(_) => "RS256",
        }
    }
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed(key) => key.sign(message).as_ref().to_vec(),
            Self::Ec(key) => {
                let sig: Signature = key.sign(message);
                sig.to_bytes().to_vec()
            }
            Self::Rsa(key) => {
                let mut sig = vec![0; key.public().modulus_len()];
                key.sign(
                    &ring::signature::RSA_PKCS1_SHA256,
                    &ring::rand::SystemRandom::new(),
                    message,
                    &mut sig,
                )
                .unwrap();
                sig
            }
        }
    }
    fn material(&self) -> (Value, String) {
        let (jwk, prefix, key) = match self {
            Self::Ed(key) => (
                json!({"kty":"OKP","crv":"Ed25519","x":BASE64_URL_SAFE_NO_PAD.encode(key.public_key().as_ref())}),
                vec![0xed, 0x01],
                key.public_key().as_ref().to_vec(),
            ),
            Self::Ec(key) => {
                let point = key.verifying_key().to_sec1_point(false);
                (
                    json!({"kty":"EC","crv":"P-256","x":BASE64_URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":BASE64_URL_SAFE_NO_PAD.encode(point.y().unwrap())}),
                    vec![0x80, 0x24],
                    key.verifying_key().to_sec1_point(true).as_bytes().to_vec(),
                )
            }
            Self::Rsa(key) => {
                use x509_parser::prelude::FromDer as _;
                let bytes = key.public_key().as_ref();
                let (_, public) = x509_parser::public_key::RSAPublicKey::from_der(bytes).unwrap();
                (
                    json!({"kty":"RSA","n":BASE64_URL_SAFE_NO_PAD.encode(public.modulus.strip_prefix(&[0]).unwrap_or(public.modulus)),"e":BASE64_URL_SAFE_NO_PAD.encode(public.exponent)}),
                    vec![0x85, 0x24],
                    bytes.to_vec(),
                )
            }
        };
        let bytes: Vec<_> = prefix.into_iter().chain(key).collect();
        (jwk, format!("z{}", bs58::encode(bytes).into_string()))
    }
}
fn input(did: &str, kind: IdentityKind, nonce: u8) -> IdentityProofInput {
    IdentityProofInput::new(
        did,
        ID,
        BASE64_URL_SAFE_NO_PAD.encode([nonce; 32]),
        RA,
        kind,
    )
}
fn payload(input: &IdentityProofInput) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(serde_json_canonicalizer::to_vec(input).unwrap())
}
fn compact(signer: &Signer, header: &Value, payload: &str) -> String {
    let message = format!(
        "{}.{payload}",
        BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap())
    );
    format!(
        "{message}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(signer.sign(message.as_bytes()))
    )
}
fn key(
    signer: &Signer,
    did: &str,
    fragment: &str,
    kind: IdentityKind,
    form: u8,
    nonce: u8,
) -> ProvenIdentityKey {
    let (jwk, multibase) = signer.material();
    let kid = format!("{did}#{fragment}");
    let mut method =
        json!({"id":kid,"controller":did,"type":"Multikey","extension":{"preserved":true}});
    if form != 1 {
        method["publicKeyJwk"] = jwk;
    }
    if form != 0 {
        method["publicKeyMultibase"] = multibase.into();
    }
    serde_json::from_value(json!({
        "verificationMethod": method,
        "signedProof": compact(signer, &json!({"alg":signer.alg(),"kid":kid}), &payload(&input(did,kind,nonce)))
    })).unwrap()
}
fn badge(did: &str, kind: IdentityKind, keys: Vec<ProvenIdentityKey>) -> IdentityBadge {
    serde_json::from_value(json!({"schemaVersion":"V2","signature":"trusted-channel-attestation","status":"VERIFIED", "keysLogId":"proof-1", "keys":keys.iter().map(|k|k.verification_method.clone()).collect::<Vec<_>>(),
      "payload":{"logId":"proof-1","producer":{"keyId":"ra-key","signature":"producer-attestation","event":{"eventType":"IDENTITY_VERIFIED","identityId":ID,"kind":kind,"value":did,"timestamp":"2026-06-23T18:30:00Z","verifiedAt":"2026-06-23T18:30:00Z","providerId":"owner","proofMethod":if kind == IdentityKind::DidKey {"did-key-sig"} else {"did-web-sig"},"raId":RA,"keys":keys}}}})).unwrap()
}
fn fixture() -> IdentityBadge {
    badge(
        DID,
        IdentityKind::DidWeb,
        vec![key(&Signer::ed(3), DID, "one", IdentityKind::DidWeb, 0, 1)],
    )
}
fn event(entry: &mut IdentityBadge) -> &mut IdentityEvent {
    &mut entry.payload.producer.event
}
fn accept(entry: &IdentityBadge) -> Result<()> {
    let mut verifier = IdentityVerifier::new(ID)?;
    verifier.observe_trusted_entry(entry)?;
    verifier.verify_badge(entry)?;
    Ok(())
}

#[test]
fn all_algorithms_and_key_representations_verify_real_signatures() {
    for signer in [Signer::ed(3), Signer::ec(), Signer::rsa()] {
        for form in 0..=2 {
            let entry = badge(
                DID,
                IdentityKind::DidWeb,
                vec![key(&signer, DID, "one", IdentityKind::DidWeb, form, 1)],
            );
            accept(&entry).unwrap();
            let mut corrupt = entry;
            let proof = &mut event(&mut corrupt).keys[0].signed_proof;
            let (message, _) = proof.rsplit_once('.').unwrap();
            *proof = format!("{message}.{}", BASE64_URL_SAFE_NO_PAD.encode([0; 64]));
            assert!(accept(&corrupt).is_err());
        }
    }
}

#[test]
fn did_key_is_derived_from_identifier_not_supplied_jwk() {
    let signer = Signer::ed(3);
    let (_, multibase) = signer.material();
    let did = format!("did:key:{multibase}");
    let mut entry = badge(
        &did,
        IdentityKind::DidKey,
        vec![key(&signer, &did, &multibase, IdentityKind::DidKey, 1, 1)],
    );
    accept(&entry).unwrap();
    for field in ["id", "controller", "type", "publicKeyMultibase"] {
        let mut corrupt = entry.clone();
        event(&mut corrupt).keys[0].verification_method[field] = "wrong".into();
        assert!(accept(&corrupt).is_err(), "accepted changed {field}");
    }
    let second = event(&mut entry).keys[0].clone();
    event(&mut entry).keys.push(second);
    assert!(accept(&entry).is_err());
}

#[test]
fn every_payload_binding_and_canonical_encoding_is_enforced() {
    let signer = Signer::ed(3);
    for field in [
        "identifier",
        "identityId",
        "nonce",
        "purpose",
        "raId",
        "scheme",
    ] {
        let mut entry = fixture();
        let mut value = serde_json::to_value(input(DID, IdentityKind::DidWeb, 1)).unwrap();
        value[field] = if field == "scheme" {
            json!("did:key")
        } else {
            json!("wrong")
        };
        event(&mut entry).keys[0].signed_proof = compact(
            &signer,
            &json!({"alg":"EdDSA","kid":format!("{DID}#one")}),
            &BASE64_URL_SAFE_NO_PAD.encode(serde_json_canonicalizer::to_vec(&value).unwrap()),
        );
        assert!(accept(&entry).is_err(), "accepted changed {field}");
    }
    let canonical = serde_json_canonicalizer::to_vec(&input(DID, IdentityKind::DidWeb, 1)).unwrap();
    let duplicate =
        String::from_utf8(canonical.clone())
            .unwrap()
            .replacen('{', "{\"raId\":\"evil\",", 1);
    for bytes in [
        serde_json::to_vec_pretty(&input(DID, IdentityKind::DidWeb, 1)).unwrap(),
        duplicate.into_bytes(),
        b"{}".to_vec(),
    ] {
        let mut entry = fixture();
        event(&mut entry).keys[0].signed_proof = compact(
            &signer,
            &json!({"alg":"EdDSA","kid":format!("{DID}#one")}),
            &BASE64_URL_SAFE_NO_PAD.encode(bytes),
        );
        assert!(accept(&entry).is_err());
    }
    // A valid 32-byte nonce is historical evidence, not a live challenge check.
    let mut historical = fixture();
    event(&mut historical).keys[0] = key(&signer, DID, "one", IdentityKind::DidWeb, 0, 9);
    accept(&historical).unwrap();
}

#[test]
fn header_key_is_never_authority_and_algorithms_are_pinned() {
    let signer = Signer::ed(3);
    let attacker = Signer::ed(4);
    let (attacker_jwk, _) = attacker.material();
    let header = json!({"alg":"EdDSA","kid":format!("{DID}#one"),"jwk":attacker_jwk});
    let mut entry = fixture();
    let p = payload(&input(DID, IdentityKind::DidWeb, 1));
    event(&mut entry).keys[0].signed_proof = compact(&signer, &header, &p);
    accept(&entry).unwrap(); // Extra header key does not override the sealed key.
    event(&mut entry).keys[0].signed_proof = compact(&attacker, &header, &p);
    assert!(matches!(
        accept(&entry),
        Err(IdentityVerificationError::SignatureInvalid)
    ));
    for header in [
        json!({"alg":"HS256","kid":format!("{DID}#one")}),
        json!({"alg":"EdDSA","kid":format!("{DID}#one"),"crit":["unknown"]}),
        json!({"alg":"EdDSA","kid":format!("{DID}#one"),"b64":false}),
        json!({"alg":"EdDSA","kid":"did:web:other.example#one"}),
    ] {
        event(&mut entry).keys[0].signed_proof = compact(&signer, &header, &p);
        assert!(accept(&entry).is_err());
    }
}

#[test]
fn missing_evidence_and_malformed_methods_fail_closed() {
    assert!(IdentityVerifier::new("").is_err());
    let base = fixture();
    let mut missing = base.clone();
    event(&mut missing).ra_id = None;
    assert!(matches!(
        accept(&missing),
        Err(IdentityVerificationError::IncompleteEvidence(_))
    ));
    for index in 0..15 {
        let mut bad = base.clone();
        match index {
            0 => bad.schema_version = "V1".into(),
            1 => bad.payload.log_id.clear(),
            2 => event(&mut bad).identity_id = "other".into(),
            3 => event(&mut bad).provider_id = None,
            4 => event(&mut bad).verified_at = None,
            5 => event(&mut bad).ans_ids.push("agent".into()),
            6 => event(&mut bad).keys.clear(),
            7 => event(&mut bad).kind = IdentityKind::Lei,
            8 => event(&mut bad).value = "wrong".into(),
            9 => event(&mut bad).keys[0].verification_method = Value::Null,
            10 => event(&mut bad).keys[0].verification_method["controller"] = "another DID".into(),
            11 => {
                event(&mut bad).keys[0]
                    .verification_method
                    .as_object_mut()
                    .unwrap()
                    .remove("publicKeyJwk");
            }
            12 => {
                event(&mut bad).keys[0].verification_method["publicKeyJwk"]["d"] = "secret".into()
            }
            13 => {
                event(&mut bad).keys[0].verification_method["publicKeyJwk"]["crv"] = "Ed448".into()
            }
            _ => event(&mut bad).keys[0].verification_method["publicKeyJwk"]["x"] = "AA".into(),
        }
        assert!(accept(&bad).is_err(), "case {index}");
    }
    for proof in [
        String::new(),
        "a.b".into(),
        "a.b.c.d".into(),
        "!.e30.AA".into(),
        "x".repeat(MAX_IDENTITY_PROOF_SIZE + 1),
    ] {
        let mut bad = base.clone();
        event(&mut bad).keys[0].signed_proof = proof;
        assert!(accept(&bad).is_err());
    }
}

#[test]
fn multi_key_rounds_are_atomic_unique_and_share_one_payload() {
    let a = Signer::ed(3);
    let b = Signer::ec();
    let mut entry = badge(
        DID,
        IdentityKind::DidWeb,
        vec![
            key(&a, DID, "one", IdentityKind::DidWeb, 0, 1),
            key(&b, DID, "two", IdentityKind::DidWeb, 2, 1),
        ],
    );
    accept(&entry).unwrap();
    let mut verifier = IdentityVerifier::new(ID).unwrap();
    event(&mut entry).keys[1] = key(&b, DID, "two", IdentityKind::DidWeb, 0, 2);
    assert!(verifier.observe_trusted_entry(&entry).is_err());
    assert!(matches!(
        verifier.verify_badge(&entry),
        Err(IdentityVerificationError::IncompleteEvidence(_))
    ));
    event(&mut entry).keys[1] = key(&b, DID, "one", IdentityKind::DidWeb, 0, 1);
    assert!(accept(&entry).is_err());
    event(&mut entry).keys = vec![key(&a, DID, "one", IdentityKind::DidWeb, 0, 1); 17];
    assert!(accept(&entry).is_err());
}

#[test]
fn current_badge_must_bind_exact_proof_event_and_full_methods() {
    let entry = fixture();
    let mut verifier = IdentityVerifier::new(ID).unwrap();
    assert!(verifier.verify_badge(&entry).is_err());
    verifier.observe_trusted_entry(&entry).unwrap();
    let proof = verifier.verify_badge(&entry).unwrap();
    assert_eq!(proof.identity_id(), ID);
    assert_eq!(proof.kind(), IdentityKind::DidWeb);
    assert_eq!(proof.value(), DID);
    assert_eq!(proof.log_id(), "proof-1");
    assert_eq!(proof.verification_methods(), entry.keys);
    for index in 0..6 {
        let mut changed = entry.clone();
        match index {
            0 => changed.keys_log_id = None,
            1 => changed.keys_log_id = Some("other".into()),
            2 => changed.keys[0]["extension"] = json!(false),
            3 => changed.keys.push(changed.keys[0].clone()),
            4 => changed.status = "ACTIVE".into(),
            _ => event(&mut changed).value = "did:web:other.example".into(),
        }
        assert!(verifier.verify_badge(&changed).is_err(), "case {index}");
    }
    let mut linked = entry.clone();
    event(&mut linked).event_type = IdentityEventType::IdentityLinked;
    event(&mut linked).keys.clear();
    assert!(verifier.observe_trusted_entry(&linked).is_err());
    event(&mut linked).ans_ids.push("agent".into());
    linked.payload.log_id = "link-2".into();
    verifier.observe_trusted_entry(&linked).unwrap();
    verifier.verify_badge(&linked).unwrap();
    let mut fresh = IdentityVerifier::new(ID).unwrap();
    fresh.observe_trusted_entry(&linked).unwrap();
    assert!(matches!(
        fresh.verify_badge(&linked),
        Err(IdentityVerificationError::IncompleteEvidence(_))
    ));
}

#[test]
fn revocation_is_terminal_across_proof_link_and_badge_reordering() {
    let entry = fixture();
    for via_badge in [false, true] {
        let mut verifier = IdentityVerifier::new(ID).unwrap();
        verifier.observe_trusted_entry(&entry).unwrap();
        let mut revoked = entry.clone();
        event(&mut revoked).event_type = IdentityEventType::IdentityRevoked;
        event(&mut revoked).keys.clear();
        revoked.status = "REVOKED".into();
        revoked.keys.clear();
        revoked.keys_log_id = None;
        if via_badge {
            assert!(matches!(
                verifier.verify_badge(&revoked),
                Err(IdentityVerificationError::Revoked)
            ));
        } else {
            verifier.observe_trusted_entry(&revoked).unwrap();
        }
        assert!(verifier.is_revoked());
        for event_type in [
            IdentityEventType::IdentityVerified,
            IdentityEventType::IdentityUpdated,
            IdentityEventType::IdentityLinked,
            IdentityEventType::IdentityUnlinked,
        ] {
            let mut later = entry.clone();
            event(&mut later).event_type = event_type;
            if matches!(
                event_type,
                IdentityEventType::IdentityLinked | IdentityEventType::IdentityUnlinked
            ) {
                event(&mut later).ans_ids = vec!["agent".into()];
                event(&mut later).keys.clear();
            }
            verifier.observe_trusted_entry(&later).unwrap();
            assert!(matches!(
                verifier.verify_badge(&entry),
                Err(IdentityVerificationError::Revoked)
            ));
        }
    }
}

#[test]
fn malformed_multikey_and_public_jwk_encodings_are_rejected() {
    for value in ["mAAAA", "z0", "z", "z111"] {
        assert!(verify_multibase(value, "EdDSA", b"message", &[0; 64]).is_err());
    }
    for bytes in [vec![0xed, 0x81, 0x00], vec![0xff; 11]] {
        assert!(decode_multikey(&format!("z{}", bs58::encode(bytes).into_string())).is_err());
    }
    let signer = Signer::ed(3);
    let (jwk, multibase) = signer.material();
    assert!(
        verify_method(
            &json!({"publicKeyJwk":jwk,"publicKeyMultibase":42}),
            "EdDSA",
            b"message",
            &[0; 64]
        )
        .is_err()
    );
    assert!(verify_multibase(&multibase, "ES256", b"message", &[0; 64]).is_err());
    for jwk in [
        Value::Null,
        json!({"kty":"EC","crv":"P-256","x":"AA","y":"AA"}),
        json!({"kty":"RSA","n":"AA","e":"AQAB"}),
        json!({"kty":"OKP","crv":"Ed25519"}),
    ] {
        assert!(verify_jwk(&jwk, "ES256", b"message", &[0; 64]).is_err());
    }
    let (other, _) = Signer::ed(4).material();
    assert!(!same_public_key(&other, &multibase).unwrap());
}

fn receipt(entry: &IdentityBadge) -> (Vec<u8>, ScittKeyStore) {
    use ciborium::Value as C;
    fn cbor(v: &C) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(v, &mut bytes).unwrap();
        bytes
    }
    let key = SigningKey::from_slice(&[9; 32]).unwrap();
    let der = key.verifying_key().to_public_key_der().unwrap();
    let hash = Sha256::digest(der.as_bytes());
    let kid = &hash[..4];
    let store = ScittKeyStore::from_c2sp_keys(&[format!(
        "tl.example.com+{}+{}",
        hex::encode(kid),
        BASE64_STANDARD.encode(der.as_bytes())
    )])
    .unwrap();
    let protected = cbor(&C::Map(vec![
        (C::Integer(1.into()), C::Integer((-7).into())),
        (C::Integer(4.into()), C::Bytes(kid.to_vec())),
        (C::Integer(395.into()), C::Integer(1.into())),
    ]));
    let payload = serde_json_canonicalizer::to_vec(entry).unwrap();
    let message = cbor(&C::Array(vec![
        C::Text("Signature1".into()),
        C::Bytes(protected.clone()),
        C::Bytes(vec![]),
        C::Bytes(payload.clone()),
    ]));
    let signature: Signature = key.sign(&message);
    let vdp = C::Map(vec![
        (C::Integer((-1).into()), C::Integer(1.into())),
        (C::Integer((-2).into()), C::Integer(0.into())),
        (C::Integer((-3).into()), C::Array(vec![])),
    ]);
    (
        cbor(&C::Array(vec![
            C::Bytes(protected),
            C::Map(vec![(C::Integer(396.into()), vdp)]),
            C::Bytes(payload),
            C::Bytes(signature.to_bytes().to_vec()),
        ])),
        store,
    )
}
#[test]
fn receipt_authentication_precedes_identity_observation() {
    let entry = fixture();
    let (bytes, keys) = receipt(&entry);
    let mut verifier = IdentityVerifier::new(ID).unwrap();
    verifier.observe_receipt(&bytes, &keys).unwrap();
    verifier.verify_badge(&entry).unwrap();
    let mut corrupt = bytes;
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        verifier.observe_receipt(&corrupt, &keys),
        Err(IdentityVerificationError::Receipt(_))
    ));
    let mut other = IdentityVerifier::new("other").unwrap();
    let (bytes, keys) = receipt(&entry);
    assert!(matches!(
        other.observe_receipt(&bytes, &keys),
        Err(IdentityVerificationError::BindingMismatch(_))
    ));
    let mut revoked = entry.clone();
    event(&mut revoked).event_type = IdentityEventType::IdentityRevoked;
    event(&mut revoked).keys.clear();
    let (bytes, keys) = receipt(&revoked);
    verifier.observe_receipt(&bytes, &keys).unwrap();
    assert!(verifier.is_revoked());
}
