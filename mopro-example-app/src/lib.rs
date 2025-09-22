// Here we're calling a macro exported with Uniffi. This macro will
// write some functions and bind them to FFI type.
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

use std::{fs, path::{PathBuf, Path}, collections::HashMap, sync::{Arc, Mutex, LazyLock}};
use sha2::{Sha256, Digest};

// Define proper error type for UniFFI compatibility
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum CrescentError {
    #[error("Prove failed: {msg}")]
    ProveError { msg: String },
    #[error("Show failed: {msg}")]
    ShowError { msg: String },
    #[error("Verify failed: {msg}")]
    VerifyError { msg: String },
    #[error("Setup failed: {msg}")]
    SetupError { msg: String },
    #[error("Cache error: {msg}")]
    CacheError { msg: String },
}

// Asset bundle for efficient mobile loading
#[derive(Clone, uniffi::Record)]
pub struct AssetBundle {
    pub main_wasm: Vec<u8>,
    pub main_r1cs: Vec<u8>,
    pub groth16_pvk: Vec<u8>,
    pub groth16_vk: Vec<u8>,
    pub prover_params: Vec<u8>,
    pub range_pk: Vec<u8>,
    pub range_vk: Vec<u8>,
    pub io_locations: String,
}

// Cache management structures
struct CrescentCache {
    paths: CachePaths,
    scheme_name: String,
    cache_hash: String,
    initialized: bool,
}

// Global cache registry
static CACHE_REGISTRY: LazyLock<Mutex<HashMap<String, Arc<CrescentCache>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

// Mobile-specific cache directory utilities
fn get_mobile_cache_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    #[cfg(target_os = "ios")]
    {
        // iOS: Use app's Caches directory (survives app updates, can be cleared by system)
        let home = std::env::var("HOME")?;
        Ok(PathBuf::from(home).join("Library/Caches/crescent"))
    }

    #[cfg(target_os = "android")]
    {
        // Android: Use internal app cache (private to app)
        let cache_dir = std::env::var("ANDROID_CACHE_DIR")
            .unwrap_or_else(|_| "/data/data/com.yourapp/cache".to_string());
        Ok(PathBuf::from(cache_dir).join("crescent"))
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        // Desktop/test: use temp dir with persistent subdirectory
        let cache_dir = std::env::temp_dir().join("crescent_cache");
        std::fs::create_dir_all(&cache_dir).ok();
        Ok(cache_dir)
    }
}

// Generate hash for asset bundle to enable cache invalidation
fn generate_asset_bundle_hash(bundle: &AssetBundle) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&bundle.main_wasm);
    hasher.update(&bundle.main_r1cs);
    hasher.update(&bundle.groth16_pvk);
    hasher.update(&bundle.groth16_vk);
    hasher.update(&bundle.prover_params);
    hasher.update(&bundle.range_pk);
    hasher.update(&bundle.range_vk);
    hasher.update(bundle.io_locations.as_bytes());
    format!("{:x}", hasher.finalize())
}

// Cache management functions
fn create_persistent_cache(scheme_name: &str, bundle: &AssetBundle) -> Result<String, Box<dyn std::error::Error>> {
    let bundle_hash = generate_asset_bundle_hash(bundle);
    let cache_id = format!("{}_{}", scheme_name, &bundle_hash[..12]); // Use first 12 chars of hash

    // Check if cache already exists
    {
        let registry = CACHE_REGISTRY.lock().map_err(|e| format!("Failed to lock cache registry: {}", e))?;
        if let Some(existing_cache) = registry.get(&cache_id) {
            if existing_cache.initialized {
                return Ok(cache_id); // Return existing cache
            }
        }
    }

    // Create new cache with persistent directory
    let cache_base_dir = get_mobile_cache_dir()?;
    let cache_dir = cache_base_dir.join(&cache_id);
    std::fs::create_dir_all(&cache_dir)?;

    let paths = CachePaths::new(cache_dir);

    // Write all assets to cache directory
    std::fs::write(&paths.wasm, &bundle.main_wasm)?;
    std::fs::write(&paths.r1cs, &bundle.main_r1cs)?;
    std::fs::write(&paths.groth16_pvk, &bundle.groth16_pvk)?;
    std::fs::write(&paths.groth16_vk, &bundle.groth16_vk)?;
    std::fs::write(&paths.prover_params, &bundle.prover_params)?;
    std::fs::write(&paths.range_pk, &bundle.range_pk)?;
    std::fs::write(&paths.range_vk, &bundle.range_vk)?;
    std::fs::write(&paths.io_locations, bundle.io_locations.as_bytes())?;

    // Create cache entry
    let cache = Arc::new(CrescentCache {
        paths,
        scheme_name: scheme_name.to_string(),
        cache_hash: bundle_hash,
        initialized: true,
    });

    // Register cache
    {
        let mut registry = CACHE_REGISTRY.lock().map_err(|e| format!("Failed to lock cache registry: {}", e))?;
        registry.insert(cache_id.clone(), cache);
    }

    Ok(cache_id)
}

fn get_cache_by_id(cache_id: &str) -> Result<Arc<CrescentCache>, Box<dyn std::error::Error>> {
    let registry = CACHE_REGISTRY.lock().map_err(|e| format!("Failed to lock cache registry: {}", e))?;
    registry.get(cache_id)
        .cloned()
        .ok_or_else(|| format!("Cache not found: {}", cache_id).into())
}

fn cleanup_cache(cache_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cache = {
        let mut registry = CACHE_REGISTRY.lock().map_err(|e| format!("Failed to lock cache registry: {}", e))?;
        registry.remove(cache_id)
    };

    if let Some(cache) = cache {
        // Remove cache directory
        let wasm_path = Path::new(&cache.paths.wasm);
        if let Some(parent) = wasm_path.parent() {
            std::fs::remove_dir_all(parent)?;
        }
    }

    Ok(())
}

// Helper functions for cached operations
fn show_credential_with_paths(
    paths: &CachePaths,
    client_state_b64: &str,
    proof_spec_json: &str,
    presentation_message: Option<String>,
    device_prv_pem: Option<&str>
) -> Result<String, Box<dyn std::error::Error>> {
    use crescent::structs::IOLocations;
    use crescent::rangeproof::RangeProofPK;
    use crescent::groth16rand::ClientState;
    use crescent::{ProofSpec, ShowProof, create_show_proof, CrescentPairing};
    use crescent::device::TestDevice;
    use crescent::utils::read_from_file;
    use ark_serialize::CanonicalDeserialize;

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

    if let Some(message) = presentation_message {
        proof_spec.presentation_message = Some(message.into_bytes());
    }

    let device_signature = if proof_spec.device_bound.unwrap_or(false) {
        if let Some(device_pem) = device_prv_pem {
            fs::write(&paths.device_prv_pem, device_pem)?;
            let device = TestDevice::new_from_file(&paths.device_prv_pem);
            Some(device.sign(proof_spec.presentation_message.as_ref().unwrap()))
        } else {
            return Err("Device-bound proof requested but no device private key provided".into());
        }
    } else {
        None
    };

    let show_proof = create_show_proof(&mut client_state, &range_pk, &io_locations, &proof_spec, device_signature)?;

    let mut serialized = Vec::new();
    show_proof.serialize_compressed(&mut serialized)
        .map_err(|e| format!("Failed to serialize show proof: {}", e))?;

    Ok(BASE64.encode(&serialized))
}

fn verify_credential_with_paths(
    paths: &CachePaths,
    show_proof_b64: &str,
    proof_spec_json: &str,
    presentation_message: Option<String>,
    issuer_pem: &str,
    config_json: &str
) -> Result<String, Box<dyn std::error::Error>> {
    use crescent::{ProofSpec, ShowProof, VerifierParams, verify_show, CrescentPairing};
    use crescent::utils::read_from_file;
    use ark_groth16::{VerifyingKey, PreparedVerifyingKey};
    use crescent::rangeproof::RangeProofVK;
    use ark_serialize::CanonicalDeserialize;

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

    let io_locations_content = std::fs::read_to_string(&paths.io_locations)?;

    let vp = VerifierParams {
        vk,
        pvk,
        range_vk,
        io_locations_str: io_locations_content,
        issuer_pem: issuer_pem.to_string(),
        config_str: config_json.to_string(),
    };

    let mut proof_spec: ProofSpec = serde_json::from_str(proof_spec_json)
        .map_err(|e| format!("Invalid proof spec JSON: {}", e))?;

    if let Some(message) = presentation_message {
        proof_spec.presentation_message = Some(message.into_bytes());
    }

    let (verify_result, data) = verify_show(&vp, &show_proof, &proof_spec);

    if verify_result {
        Ok(data)
    } else {
        Err("Verification failed".into())
    }
}

#[uniffi::export]
fn crescent_initialize_cache(
    scheme_name: String,
    asset_bundle: AssetBundle
) -> Result<String, CrescentError> {
    create_persistent_cache(&scheme_name, &asset_bundle)
        .map_err(|e| CrescentError::CacheError { msg: e.to_string() })
}

#[uniffi::export]
fn crescent_prove(
    cache_id: String,
    jwt_token: String,
    issuer_pem: String,
    config_json: String,
    device_pub_pem: Option<String>
) -> Result<String, CrescentError> {
    let cache = get_cache_by_id(&cache_id)
        .map_err(|e| CrescentError::CacheError { msg: e.to_string() })?;

    let config = parse_config(&config_json)
        .map_err(|e| CrescentError::ProveError { msg: e.to_string() })?;

    let (prover_inputs_json, prover_aux_json, _public_ios_json) =
        prepare_prover_inputs(&config, &jwt_token, &issuer_pem, device_pub_pem.as_deref())
            .map_err(|e| CrescentError::ProveError { msg: e.to_string() })?;

    let prover_inputs = GenericInputsJSON { prover_inputs: prover_inputs_json };
    let prover_aux_string = json!(prover_aux_json).to_string();

    let client_state = create_client_state(&cache.paths, &prover_inputs, Some(&prover_aux_string), "jwt")
        .map_err(|e| CrescentError::ProveError { msg: e.to_string() })?;

    let mut serialized = Vec::new();
    client_state.serialize_compressed(&mut serialized)
        .map_err(|e| CrescentError::ProveError { msg: format!("Failed to serialize client state: {}", e) })?;

    Ok(BASE64.encode(&serialized))
}

#[uniffi::export]
fn crescent_show(
    cache_id: String,
    client_state_b64: String,
    proof_spec_json: String,
    presentation_message: Option<String>,
    device_prv_pem: Option<String>
) -> Result<String, CrescentError> {
    let cache = get_cache_by_id(&cache_id)
        .map_err(|e| CrescentError::CacheError { msg: e.to_string() })?;

    show_credential_with_paths(
        &cache.paths,
        &client_state_b64,
        &proof_spec_json,
        presentation_message,
        device_prv_pem.as_deref()
    ).map_err(|e| CrescentError::ShowError { msg: e.to_string() })
}

#[uniffi::export]
fn crescent_verify(
    cache_id: String,
    show_proof_b64: String,
    proof_spec_json: String,
    presentation_message: Option<String>,
    issuer_pem: String,
    config_json: String
) -> Result<String, CrescentError> {
    let cache = get_cache_by_id(&cache_id)
        .map_err(|e| CrescentError::CacheError { msg: e.to_string() })?;

    verify_credential_with_paths(
        &cache.paths,
        &show_proof_b64,
        &proof_spec_json,
        presentation_message,
        &issuer_pem,
        &config_json
    ).map_err(|e| CrescentError::VerifyError { msg: e.to_string() })
}

#[uniffi::export]
fn crescent_cleanup_cache(cache_id: String) -> Result<(), CrescentError> {
    cleanup_cache(&cache_id)
        .map_err(|e| CrescentError::CacheError { msg: e.to_string() })
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

        // Load all assets
        let jwt_token = fs::read_to_string("../creds/test-vectors/rs256-sd/token.jwt")
            .expect("Failed to read JWT token");
        let issuer_pem = fs::read_to_string("../creds/test-vectors/rs256-sd/issuer.pub")
            .expect("Failed to read issuer PEM");
        let config_json = fs::read_to_string("../creds/test-vectors/rs256-sd/config.json")
            .expect("Failed to read config");
        let device_pub_pem = fs::read_to_string("../creds/test-vectors/rs256-sd/device.pub").ok();
        let main_wasm = fs::read("../creds/test-vectors/rs256-sd/main.wasm")
            .expect("Failed to read main.wasm");
        let main_r1cs = fs::read("../creds/test-vectors/rs256-sd/main_c.r1cs")
            .expect("Failed to read main_c.r1cs");
        let groth16_pvk = fs::read("../creds/test-vectors/rs256-sd/cache/groth16_pvk.bin")
            .expect("Failed to read groth16_pvk.bin");
        let groth16_vk = fs::read("../creds/test-vectors/rs256-sd/cache/groth16_vk.bin")
            .expect("Failed to read groth16_vk.bin");
        let prover_params = fs::read("../creds/test-vectors/rs256-sd/cache/prover_params.bin")
            .expect("Failed to read prover_params.bin");
        let range_pk = fs::read("../creds/test-vectors/rs256-sd/cache/range_pk.bin")
            .expect("Failed to read range_pk.bin");
        let range_vk = fs::read("../creds/test-vectors/rs256-sd/cache/range_vk.bin")
            .expect("Failed to read range_vk.bin");
        let io_locations = fs::read_to_string("../creds/test-vectors/rs256-sd/io_locations.sym")
            .expect("Failed to read io_locations.sym");
        let device_prv_pem = fs::read_to_string("../creds/test-vectors/rs256-sd/device.prv").ok();

        // Create asset bundle
        let asset_bundle = AssetBundle {
            main_wasm,
            main_r1cs,
            groth16_pvk: groth16_pvk.clone(),
            groth16_vk,
            prover_params,
            range_pk: range_pk.clone(),
            range_vk,
            io_locations,
        };

        println!("Testing crescent_initialize_cache...");
        let cache_id = crescent_initialize_cache(scheme_name, asset_bundle)
            .expect("crescent_initialize_cache failed");
        println!("Cache initialized with ID: {}", cache_id);

        println!("Testing crescent_prove...");
        let client_state_b64 = crescent_prove(
            cache_id.clone(),
            jwt_token,
            issuer_pem.clone(),
            config_json.clone(),
            device_pub_pem
        ).expect("crescent_prove failed");
        println!("Client state encoded length: {}", client_state_b64.len());

        let proof_spec_json = r#"{"revealed": ["family_name", "tenant_ctry"]}"#.to_string();
        let presentation_message = Some("test presentation".to_string());

        println!("Testing crescent_show...");
        let show_proof_b64 = crescent_show(
            cache_id.clone(),
            client_state_b64,
            proof_spec_json.clone(),
            presentation_message.clone(),
            device_prv_pem
        ).expect("crescent_show failed");
        println!("Show proof encoded length: {}", show_proof_b64.len());

        println!("Testing crescent_verify...");
        let verification_result = crescent_verify(
            cache_id.clone(),
            show_proof_b64,
            proof_spec_json,
            presentation_message,
            issuer_pem,
            config_json
        ).expect("crescent_verify failed");
        println!("Verification result: {}", verification_result);

        assert!(!verification_result.is_empty());
        assert!(verification_result.contains("family_name"));

        println!("Testing crescent_cleanup_cache...");
        crescent_cleanup_cache(cache_id)
            .expect("crescent_cleanup_cache failed");
        println!("Cache cleaned up successfully");
    }

}
