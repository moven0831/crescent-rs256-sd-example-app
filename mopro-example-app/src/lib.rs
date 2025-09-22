// Here we're calling a macro exported with Uniffi. This macro will
// write some functions and bind them to FFI type.
// These functions include:
// - `generate_circom_proof`
// - `verify_circom_proof`
// - `generate_halo2_proof`
// - `verify_halo2_proof`
// - `generate_noir_proof`
// - `verify_noir_proof`
mopro_ffi::app!();

use crescent::{
    create_client_state, create_show_proof, verify_show,
    CachePaths, ProofSpec, ShowProof, VerifierParams, CrescentPairing
};
use crescent::device::TestDevice;
use crescent::structs::{GenericInputsJSON, IOLocations};
use crescent::rangeproof::RangeProofPK;
use crescent::prep_inputs::{parse_config, prepare_prover_inputs};
use crescent::groth16rand::ClientState;
use crescent::utils::read_from_file;
use ark_groth16::{VerifyingKey, PreparedVerifyingKey};
use crescent::rangeproof::RangeProofVK;

use serde_json::json;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use std::{fs, path::PathBuf};

/// You can also customize the bindings by #[uniffi::export]
/// Reference: https://mozilla.github.io/uniffi-rs/latest/proc_macro/index.html
#[uniffi::export]
fn mopro_uniffi_hello_world() -> String {
    "Hello, World!".to_string()
}

// CRESCENT INTEGRATION

#[uniffi::export]
fn crescent_prove(scheme_name: String, jwt_token: String, issuer_pem: String) -> Result<String, String> {
    prove_credential(&scheme_name, &jwt_token, &issuer_pem)
        .map_err(|e| format!("Prove failed: {}", e))
}

#[uniffi::export]
fn crescent_show(
    scheme_name: String,
    client_state_b64: String,
    proof_spec_json: String,
    presentation_message: Option<String>
) -> Result<String, String> {
    show_credential(&scheme_name, &client_state_b64, &proof_spec_json, presentation_message)
        .map_err(|e| format!("Show failed: {}", e))
}

#[uniffi::export]
fn crescent_verify(
    scheme_name: String,
    show_proof_b64: String,
    proof_spec_json: String,
    presentation_message: Option<String>
) -> Result<String, String> {
    verify_credential(&scheme_name, &show_proof_b64, &proof_spec_json, presentation_message)
        .map_err(|e| format!("Verify failed: {}", e))
}

fn get_scheme_paths(scheme_name: &str) -> Result<CachePaths, String> {
    let base_path = PathBuf::from(format!("../creds/test-vectors/{}", scheme_name));
    if !base_path.exists() {
        return Err(format!("Scheme '{}' not found. Please run zksetup first.", scheme_name));
    }
    Ok(CachePaths::new(base_path))
}

fn prove_credential(scheme_name: &str, jwt_token: &str, issuer_pem: &str) -> Result<String, Box<dyn std::error::Error>> {
    let paths = get_scheme_paths(scheme_name)?;

    let config_str = fs::read_to_string(&paths.config)
        .map_err(|_| format!("Unable to read config from {}", paths.config))?;
    let config = parse_config(&config_str)?;

    let device_pub_pem = fs::read_to_string(&paths.device_pub_pem).ok();
    let (prover_inputs_json, prover_aux_json, _public_ios_json) =
        prepare_prover_inputs(&config, jwt_token, issuer_pem, device_pub_pem.as_deref())?;

    let prover_inputs = GenericInputsJSON { prover_inputs: prover_inputs_json };
    let prover_aux_string = json!(prover_aux_json).to_string();

    let client_state = create_client_state(&paths, &prover_inputs, Some(&prover_aux_string), "jwt")?;

    let mut serialized = Vec::new();
    client_state.serialize_compressed(&mut serialized)
        .map_err(|e| format!("Failed to serialize client state: {}", e))?;

    Ok(BASE64.encode(&serialized))
}

fn show_credential(
    scheme_name: &str,
    client_state_b64: &str,
    proof_spec_json: &str,
    presentation_message: Option<String>
) -> Result<String, Box<dyn std::error::Error>> {
    let paths = get_scheme_paths(scheme_name)?;
    let io_locations = IOLocations::new(&paths.io_locations);

    let serialized = BASE64.decode(client_state_b64)
        .map_err(|e| format!("Invalid base64 client state: {}", e))?;
    let mut client_state: ClientState<CrescentPairing> =
        CanonicalDeserialize::deserialize_compressed(&serialized[..])
            .map_err(|e| format!("Failed to deserialize client state: {}", e))?;

    let range_pk: RangeProofPK<CrescentPairing> = read_from_file(&paths.range_pk)
        .map_err(|e| format!("Failed to load range proving key: {}", e))?;

    let mut proof_spec: ProofSpec = serde_json::from_str(proof_spec_json)
        .map_err(|e| format!("Invalid proof spec JSON: {}", e))?;

    if presentation_message.is_some() {
        proof_spec.presentation_message = Some(presentation_message.unwrap().into_bytes());
    }

    let device_signature = if proof_spec.device_bound.unwrap_or(false) {
        let device = TestDevice::new_from_file(&paths.device_prv_pem);
        Some(device.sign(proof_spec.presentation_message.as_ref().unwrap()))
    } else {
        None
    };

    let show_proof = create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec, device_signature)?;

    let mut serialized = Vec::new();
    show_proof.serialize_compressed(&mut serialized)
        .map_err(|e| format!("Failed to serialize show proof: {}", e))?;

    Ok(BASE64.encode(&serialized))
}

fn verify_credential(
    scheme_name: &str,
    show_proof_b64: &str,
    proof_spec_json: &str,
    presentation_message: Option<String>
) -> Result<String, Box<dyn std::error::Error>> {
    let paths = get_scheme_paths(scheme_name)?;

    let serialized = BASE64.decode(show_proof_b64)
        .map_err(|e| format!("Invalid base64 show proof: {}", e))?;
    let show_proof: ShowProof<CrescentPairing> =
        CanonicalDeserialize::deserialize_compressed(&serialized[..])
            .map_err(|e| format!("Failed to deserialize show proof: {}", e))?;

    let pvk: PreparedVerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_pvk)
        .map_err(|e| format!("Failed to load prepared verifying key: {}", e))?;
    let vk: VerifyingKey<CrescentPairing> = read_from_file(&paths.groth16_vk)
        .map_err(|e| format!("Failed to load verifying key: {}", e))?;
    let range_vk: RangeProofVK<CrescentPairing> = read_from_file(&paths.range_vk)
        .map_err(|e| format!("Failed to load range verification key: {}", e))?;

    let io_locations_str = fs::read_to_string(&paths.io_locations)
        .map_err(|e| format!("Failed to read io_locations: {}", e))?;
    let issuer_pem = fs::read_to_string(&paths.issuer_pem)
        .map_err(|e| format!("Failed to read issuer PEM: {}", e))?;
    let config_str = fs::read_to_string(&paths.config)
        .map_err(|e| format!("Failed to read config: {}", e))?;

    let vp = VerifierParams { vk, pvk, range_vk, io_locations_str, issuer_pem, config_str };

    let mut proof_spec: ProofSpec = serde_json::from_str(proof_spec_json)
        .map_err(|e| format!("Invalid proof spec JSON: {}", e))?;

    if presentation_message.is_some() {
        proof_spec.presentation_message = Some(presentation_message.unwrap().into_bytes());
    }

    let (verify_result, data) = verify_show(&vp, &show_proof, &proof_spec);

    if verify_result {
        Ok(data)
    } else {
        Err("Verification failed".into())
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mopro_uniffi_hello_world() {
        assert_eq!(mopro_uniffi_hello_world(), "Hello, World!");
    }

    #[test]
    fn test_crescent_integration() {
        let scheme_name = "rs256-sd".to_string();

        let jwt_token = fs::read_to_string("../creds/test-vectors/rs256-sd/token.jwt")
            .expect("Failed to read JWT token");
        let issuer_pem = fs::read_to_string("../creds/test-vectors/rs256-sd/issuer.pub")
            .expect("Failed to read issuer PEM");

        println!("Testing crescent_prove...");
        let client_state_b64 = crescent_prove(scheme_name.clone(), jwt_token, issuer_pem)
            .expect("crescent_prove failed");
        println!("Client state encoded length: {}", client_state_b64.len());

        let proof_spec_json = r#"{"revealed": ["family_name", "tenant_ctry"]}"#.to_string();
        let presentation_message = Some("test presentation".to_string());

        println!("Testing crescent_show...");
        let show_proof_b64 = crescent_show(
            scheme_name.clone(),
            client_state_b64,
            proof_spec_json.clone(),
            presentation_message.clone()
        ).expect("crescent_show failed");
        println!("Show proof encoded length: {}", show_proof_b64.len());

        println!("Testing crescent_verify...");
        let verification_result = crescent_verify(
            scheme_name,
            show_proof_b64,
            proof_spec_json,
            presentation_message
        ).expect("crescent_verify failed");
        println!("Verification result: {}", verification_result);

        assert!(!verification_result.is_empty());
        assert!(verification_result.contains("family_name"));
    }
}
