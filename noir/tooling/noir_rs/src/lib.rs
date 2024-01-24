use std::io::Read;

use acir::{circuit::Circuit, native_types::WitnessMap};
use base64::{engine::general_purpose, Engine};
use flate2::bufread::GzDecoder;
use noir_rs_acir_composer::AcirComposer;
use noir_rs_acvm_runtime::execute::execute_circuit;
use noir_rs_barretenberg::{
    circuit::circuit_size::get_circuit_sizes,
    srs::{srs_init, Srs, localsrs::LocalSrs, netsrs::NetSrs},
};
use noir_rs_blackbox_solver::BlackboxSolver;

pub use acir::*;
pub use acvm::*;

const DEFAULT_SRS_URL: &str = "https://aztec-ignition.s3.amazonaws.com/MAIN%20IGNITION/monomial/transcript00.dat";

fn prove_with_srs<S: Srs>(
    circuit_bytecode: String,
    initial_witness: WitnessMap,
    mut srs: S,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let acir_buffer = general_purpose::STANDARD.decode(circuit_bytecode).map_err(|e| e.to_string())?;
    let circuit = Circuit::deserialize_circuit(&acir_buffer).map_err(|e| e.to_string())?;
    let mut decoder = GzDecoder::new(acir_buffer.as_slice());
    let mut acir_buffer_uncompressed = Vec::<u8>::new();
    decoder.read_to_end(&mut acir_buffer_uncompressed).map_err(|e| e.to_string())?;

    let blackbox_solver = BlackboxSolver::new();
    let solved_witness = execute_circuit(&blackbox_solver, circuit, initial_witness).map_err(|e| e.to_string())?;
    let serialized_solved_witness = bincode::serialize(&solved_witness).map_err(|e| e.to_string())?;

    let circuit_size = get_circuit_sizes(&acir_buffer_uncompressed).map_err(|e| e.to_string())?;
    println!("circuit_size: {0}", circuit_size.total);
    let log_value = (circuit_size.total as f64).log2().ceil() as u32;
    let subgroup_size = 2u32.pow(log_value);
    srs.load_data(subgroup_size + 1);
    srs_init(srs.g1_data(), srs.num_points(), srs.g2_data()).map_err(|e| e.to_string())?;
    let acir_composer = AcirComposer::new(&subgroup_size).map_err(|e| e.to_string())?;

    Ok((
        acir_composer
            .create_proof(&acir_buffer_uncompressed, &serialized_solved_witness, false)
            .map_err(|e| e.to_string())?,
        acir_composer.get_verification_key().map_err(|e| e.to_string())?,
    ))
}

/// Generate a proof for a given circuit and witness, using a local transcript file to load the needed
/// SRS data based on the circuit size.
///
/// # Arguments
/// * `srs_path` - Local file path of SRS transcript.
/// * `circuit_bytecode` - A `String` of the base64-encoded compressed ACIR circuit bytecode.
/// * `initial_witness` - A `WitnessMap` of the initial witness inputs to the circuit.
///
/// # Returns
/// * `Ok((Vec<u8>, Vec<u8>))` - On success, returns the tuple (proof, verification_key)
/// * `Err(String)` - On error, returns a `String` describing the error.
pub fn prove_local_srs(
    srs_path: &str,
    circuit_bytecode: String,
    initial_witness: WitnessMap,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let srs = LocalSrs::new(srs_path);
    prove_with_srs(circuit_bytecode, initial_witness, srs)
}

/// Generate a proof for a given circuit and witness, downloading the needed SRS data from Aztec's official AWS
/// transcript URL based on the circuit size.
///
/// # Arguments
/// * `circuit_bytecode` - A `String` of the base64-encoded compressed ACIR circuit bytecode.
/// * `initial_witness` - A `WitnessMap` of the initial witness inputs to the circuit.
///
/// # Returns
/// * `Ok((Vec<u8>, Vec<u8>))` - On success, returns the tuple (proof, verification_key)
/// * `Err(String)` - On error, returns a `String` describing the error.
pub fn prove(
    circuit_bytecode: String,
    initial_witness: WitnessMap,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let srs = NetSrs::new(DEFAULT_SRS_URL);
    prove_with_srs(circuit_bytecode, initial_witness, srs)
}

/// Generate a proof for a given circuit and witness, downloading the needed SRS data based on the circuit size.
///
/// # Arguments
/// * `srs_url` - Optional URL to SRS transcript file. If `None`, defaults to Aztec's official AWS transcript URL.
/// * `circuit_bytecode` - A `String` of the base64-encoded compressed ACIR circuit bytecode.
/// * `initial_witness` - A `WitnessMap` of the initial witness inputs to the circuit.
///
/// # Returns
/// * `Ok((Vec<u8>, Vec<u8>))` - On success, returns the tuple (proof, verification_key)
/// * `Err(String)` - On error, returns a `String` describing the error.
pub fn prove_net_srs(
    srs_url: Option<&str>,
    circuit_bytecode: String,
    initial_witness: WitnessMap,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let srs_url = srs_url.unwrap_or(DEFAULT_SRS_URL);
    let srs = NetSrs::new(&srs_url);
    prove_with_srs(circuit_bytecode, initial_witness, srs)
}

pub fn verify(
    proof: Vec<u8>,
    verification_key: Vec<u8>,
) -> Result<bool, String> {
    let subgroup_size_hint = 1;
    let acir_composer = AcirComposer::new(&subgroup_size_hint).map_err(|e| e.to_string())?;
    acir_composer.load_verification_key(&verification_key).map_err(|e| e.to_string())?;
    acir_composer.verify_proof(&proof, false).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use acir::native_types::{Witness, WitnessMap};
    use acvm::FieldElement;
    use serial_test::serial;
    use std::time::Instant;

    use crate::{prove, prove_local_srs, prove_net_srs, verify};
    const SRS_PATH: &str = "transcript00.dat";

    #[test]
    #[serial]
    fn test_prove_verify_net_srs_simple1() {
        const BYTECODE: &str = "H4sIAAAAAAAA/7VTQQ4DIQjE3bXHvgUWXfHWr9TU/f8TmrY2Ma43cRJCwmEYBrAAYOGKteRHyYyHcznsmZieuMckHp1Ph5CQF//ahTmLkxBTDBjJcabTRz7xB1Nx4RhoUdS16un6cpmOl6bxEsdAmpprvVuJD5bOLdwmzAJNn9a/e6em2nzGcrYJvBb0jn7W3FZ/R1hRXjSP+mBB/5FMpbN+oj/eG6c6pXEFAAA=";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::zero());
        initial_witness.insert(Witness(2), FieldElement::one());

        let (proof, vk) = prove(String::from(BYTECODE), initial_witness).unwrap();
        let valid = verify(proof, vk).unwrap();
        println!("Verified {valid}");
        assert!(valid);
    }
    #[test]
    #[serial]
    fn test_prove_verify_net_srs_simple2() {
        const BYTECODE: &str = "H4sIAAAAAAAA/7VTQQ4DIQjE3bXHvgUWXfHWr9TU/f8TmrY2Ma43cRJCwmEYBrAAYOGKteRHyYyHcznsmZieuMckHp1Ph5CQF//ahTmLkxBTDBjJcabTRz7xB1Nx4RhoUdS16un6cpmOl6bxEsdAmpprvVuJD5bOLdwmzAJNn9a/e6em2nzGcrYJvBb0jn7W3FZ/R1hRXjSP+mBB/5FMpbN+oj/eG6c6pXEFAAA=";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::zero());
        initial_witness.insert(Witness(2), FieldElement::one());

        let (proof, vk) = prove_net_srs(None, String::from(BYTECODE), initial_witness).unwrap();
        let valid = verify(proof, vk).unwrap();
        println!("Verified {valid}");
        assert!(valid);
    }

    #[test]
    #[serial]
    fn test_prove_verify_local_srs_simple() {
        const BYTECODE: &str = "H4sIAAAAAAAA/7VTQQ4DIQjE3bXHvgUWXfHWr9TU/f8TmrY2Ma43cRJCwmEYBrAAYOGKteRHyYyHcznsmZieuMckHp1Ph5CQF//ahTmLkxBTDBjJcabTRz7xB1Nx4RhoUdS16un6cpmOl6bxEsdAmpprvVuJD5bOLdwmzAJNn9a/e6em2nzGcrYJvBb0jn7W3FZ/R1hRXjSP+mBB/5FMpbN+oj/eG6c6pXEFAAA=";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::from(0u128));
        initial_witness.insert(Witness(2), FieldElement::from(1u128));

        let (proof, vk) = prove_local_srs(SRS_PATH, String::from(BYTECODE), initial_witness).unwrap();
        println!("Proved!");
        let valid = verify(proof, vk).unwrap();
        println!("Verified {valid}");
        assert!(valid);
    }

    #[test]
    #[serial]
    fn test_prove_verify_local_srs_54830() {
        const BYTECODE: &str = "H4sIAAAAAAAA/+3c2W7aQBQGYJMAXjFgzL6EbFxjbGxzl4te9DVCQ6RKVVRVfX91xrHVKZ1mLGU81h91pCPiIJ3z/WNALCEbTdMM7XU1SF3klwZzfHF2fHl23GR6aEwvuh7yy3AbR9Ep2Z2CMHjc7g7HdL+N9sc4DdJgn+6fdmkYntIoTQ7HQ7I9BFF4Cp73h/B5+7paTK/tO1eVzrY8Z0RtnXx/6Wrl+1ycj+I8FPtPZ6/zokvPf2+SskjZpJy8p0uqS6pHqk/KIzUg5ZMakhqRGpOakJqSmpGak1qQWpJakbrKZ12TuiF1S+qO1D2pTe5rMPu81t6+jWzftwJdk38bkW00AIwmgNECMNoARgfA2AEwugDGLoCxB2DsAxg9AOMAwOgDGIcAxhGAcQxgnAAYpwDGGYBxDmBcABiXAMYVgPEKwLgGMF4DGG8AjLcAxjsA4z2AcVOB8VOOpO93XWh/rjbzs5y5u+y9Ycn7kr0v3sp7ubm7KXVGlNL9uTzbn8bZ8QPzc5PZw5bkvG3t97mR0zM50h464y+yFnabub7NXOpyswUNZmbRtzjWK5u729EehiC/wXEYCvMblc2Ns/NvCvKbHIepML9Z2dz4QHtYgvwWx2EpzG9VNjc+FRnfym9zHLbC/HZlc+OI9nAE+R2Ow1GYn/WVteo1W+XPDR9pj44gf4fj6CjMz/rKWvWarfLnxgHt4QryuxyHqzC/W9ncJHte0RXk73IcXYX5Wd9HtHZqtsqfm2TPV3qC/D2Oo6cwP+sra9Vrtsqfu/tCe/QF+fscR19hftZX1qrXbJU/N87OlSfI73EcnsL8XmVz4z3tMRDkH3AcA4X5WV9Zq1WzVf7cOKE9fEF+n+PwFeb3K5ubZK/ZhoL8Q45jqDD/sLK5cUp7jAT5RxzHSGF+1lfWqgNZnZqt8ueGIe0xFuQfcxxjhfnHlc0Ns9dsE0H+CccxUZif9ZW19oCsOpDVB7J2a7bKn5tkn2VOBfmnHMdUYX7WV9bqAVl1IKsDZG0DWZFuAwaQ1QSyWkBWG8j6//H1Y+6r/LlJ9h7eTJB/xnHMFOZnfWWtVs1W+XOT7LX2XJB/znHMFeZnfWWtJpB1AGS1gKwekNUGsiLdt5Burz6QFem+hfT4irSvLpBVB7L2gKx176v8uUn2ufZCkH/BcSwU5md9Za0mkNUGsvpA1iGQVQeyOjVb5c8Ns7/vWAryLzmOpcL8y8rmJk+0x0qQf8VxrBTmZ30o1iq+k0g/TykeL77/+Pry89vL+VYU/yqRrjXzu+L6zwy74Ona31+zlLZXzTMYhTS1f69f+QxrnihSAAA=";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::from(0u128));
        initial_witness.insert(Witness(2), FieldElement::from(1u128));
        initial_witness.insert(Witness(3), FieldElement::from(2u128));
        initial_witness.insert(Witness(4), FieldElement::from(3u128));

        let start = Instant::now();
        let (proof, vk) = prove_local_srs(SRS_PATH, String::from(BYTECODE), initial_witness).unwrap();
        println!("Proved in: {:?}", start.elapsed());

        let start = Instant::now();
        let valid = verify(proof, vk).unwrap();
        assert!(valid);
        println!("Verified in: {:?}", start.elapsed());
    }

    #[test]
    #[serial]
    fn test_prove_verify_local_srs_111662() {
        const BYTECODE: &str = "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";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::from(0u128));
        initial_witness.insert(Witness(2), FieldElement::from(1u128));
        initial_witness.insert(Witness(3), FieldElement::from(2u128));
        initial_witness.insert(Witness(4), FieldElement::from(3u128));

        let start = Instant::now();
        let (proof, vk) = prove_local_srs(SRS_PATH, String::from(BYTECODE), initial_witness).unwrap();
        println!("Proved in: {:?}", start.elapsed());

        let start = Instant::now();
        let valid = verify(proof, vk).unwrap();
        assert!(valid);
        println!("Verified in: {:?}", start.elapsed());
    }

    #[test]
    #[serial]
    fn test_prove_verify_local_srs_184497() {
        const BYTECODE: &str = "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";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::from(0u128));
        initial_witness.insert(Witness(2), FieldElement::from(1u128));
        initial_witness.insert(Witness(3), FieldElement::from(2u128));
        initial_witness.insert(Witness(4), FieldElement::from(3u128));

        let start = Instant::now();
        let (proof, vk) = prove_local_srs(SRS_PATH, String::from(BYTECODE), initial_witness).unwrap();
        println!("Proved in: {:?}", start.elapsed());

        let start = Instant::now();
        let valid = verify(proof, vk).unwrap();
        assert!(valid);
        println!("Verified in: {:?}", start.elapsed());
    }

    #[test]
    #[serial]
    fn test_prove_verify_local_srs_365461() {
        const BYTECODE: &str = "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";
        let mut initial_witness = WitnessMap::new();
        initial_witness.insert(Witness(1), FieldElement::from(0u128));
        initial_witness.insert(Witness(2), FieldElement::from(1u128));
        initial_witness.insert(Witness(3), FieldElement::from(2u128));
        initial_witness.insert(Witness(4), FieldElement::from(3u128));

        let start = Instant::now();
        let (proof, vk) = prove_local_srs(SRS_PATH, String::from(BYTECODE), initial_witness).unwrap();
        println!("Proved in: {:?}", start.elapsed());

        let start = Instant::now();
        let valid = verify(proof, vk).unwrap();
        assert!(valid);
        println!("Verified in: {:?}", start.elapsed());
    }
}
