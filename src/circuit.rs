use crate::gadget;
use dusk_bls12_381::BlsScalar;
use dusk_plonk::error::Error as PlonkError;
use dusk_plonk::prelude::*;
use encryptor::PoseidonEncryption;
use rand_core::OsRng;
use std::fs;
use std::path::Path;

const DATA_PATH: &str = "./data";
const PARAMETER_FILE_PATH: &str = "./data/parameter.data";
const PROVER_KEY_FILE_PATH: &str = "./data/prover_key.data";
const VERIFIER_DATA_FILE_PATH: &str = "./data/verifier_data.data";

pub struct PoseidonCircuit<'a> {
  pub symmetric_key: JubJubAffine,
  pub nonce: BlsScalar,
  pub plain_text: &'a [BlsScalar],
  pub cipher_text: &'a [BlsScalar],

  pub public_parameter: Option<PublicParameters>,
  pub prover_key: Option<ProverKey>,
  pub verifier_data: Option<VerifierData>,
}

impl<'a> PoseidonCircuit<'a> {
  pub fn new() -> Self {
    let symmetric_key = JubJubAffine::default();
    let nonce = BlsScalar::default();

    const PLAIN_TEXT: [BlsScalar; PoseidonEncryption::capacity()] = [BlsScalar::zero(); PoseidonEncryption::capacity()];
    const CIPHER_TEXT: [BlsScalar; PoseidonEncryption::cipher_size()] = [BlsScalar::zero(); PoseidonEncryption::cipher_size()];

    Self {
      symmetric_key,
      nonce,
      plain_text: &PLAIN_TEXT,
      cipher_text: &CIPHER_TEXT,

      public_parameter: None,
      prover_key: None,
      verifier_data: None,
    }
  }

  pub fn setup_parameter(&mut self) {
    let size = 14;
    self.public_parameter = PublicParameters::setup(1 << size, &mut OsRng).ok();
    let (prover_key, verifier_data) = self.compile(&self.public_parameter.clone().unwrap()).unwrap();

    self.prover_key = Some(prover_key);
    self.verifier_data = Some(verifier_data);
  }

  pub fn export_parameter(&self) {
    if fs::create_dir_all(DATA_PATH).is_ok() == false {
      return
    };

    let bytes = self.public_parameter.clone().unwrap().to_raw_var_bytes();
    std::fs::write(PARAMETER_FILE_PATH, bytes).unwrap();

    let bytes = self.prover_key.clone().unwrap().to_var_bytes();
    std::fs::write(PROVER_KEY_FILE_PATH, bytes).unwrap();

    let bytes = self.verifier_data.clone().unwrap().to_var_bytes();
    std::fs::write(VERIFIER_DATA_FILE_PATH, bytes).unwrap();
  }

  pub fn import_parameter(&mut self) {
    if Path::new(PARAMETER_FILE_PATH).exists() == false || Path::new(PROVER_KEY_FILE_PATH).exists() == false || Path::new(VERIFIER_DATA_FILE_PATH).exists() == false {
      self.setup_parameter();
      return;
    }

    let data = std::fs::read(PARAMETER_FILE_PATH).unwrap();
    self.public_parameter = unsafe { Some(PublicParameters::from_slice_unchecked(&data)) };

    let data = std::fs::read(PROVER_KEY_FILE_PATH).unwrap();
    self.prover_key = ProverKey::from_slice(&data).ok();

    let data = std::fs::read(VERIFIER_DATA_FILE_PATH).unwrap();
    self.verifier_data = VerifierData::from_slice(&data).ok();
  }

  pub fn set_input(&mut self, symmetric_key: JubJubAffine, nonce: BlsScalar, plain_text: &'a [BlsScalar], cipher_text: &'a [BlsScalar]) {
    self.symmetric_key = symmetric_key;
    self.nonce = nonce;
    self.plain_text = plain_text;
    self.cipher_text = cipher_text;
  }
}

impl<'a> Circuit for PoseidonCircuit<'a> {
  const CIRCUIT_ID: [u8; 32] = [0xff; 32];

  fn gadget(&mut self, composer: &mut TurboComposer) -> Result<(), PlonkError> {
    let zero = TurboComposer::constant_zero();
    let nonce = composer.append_witness(self.nonce);
    let symmetric_key = composer.append_point(self.symmetric_key);

    let mut message_circuit = [zero; PoseidonEncryption::capacity()];

    self.plain_text.iter().zip(message_circuit.iter_mut()).for_each(|(m, v)| {
      *v = composer.append_witness(*m);
    });

    let cipher_gadget = gadget::encrypt(composer, &symmetric_key, nonce, &message_circuit);

    self.cipher_text.iter().zip(cipher_gadget.iter()).for_each(|(c, g)| {
      let x = composer.append_public_witness(*c);
      composer.assert_equal(x, *g);
    });

    Ok(())
  }

  fn public_inputs(&self) -> Vec<PublicInputValue> {
    vec![]
  }

  fn padded_gates(&self) -> usize {
    1 << 14
  }
}

#[allow(unused_imports)]
mod tests {
  use super::*;
  use dusk_jubjub::{dhke, GENERATOR_EXTENDED};

  #[test]
  fn gadget_test_with_setup_parameter() -> Result<(), PlonkError> {
    // Generate a secret and a public key for Bob
    let bob_secret = JubJubScalar::random(&mut OsRng);

    // Generate a secret and a public key for Alice
    let alice_secret = JubJubScalar::random(&mut OsRng);
    let alice_public = GENERATOR_EXTENDED * alice_secret;

    // Generate a shared secret
    let symmetric_key = dhke(&bob_secret, &alice_public);

    // Generate a secret message
    let message = "sample message".to_string();

    // Perform the encryption
    let poseidon_encryption = PoseidonEncryption::new();
    let message_scalar = poseidon_encryption.get_message_bls_scalar_vector(message.as_bytes());

    let (cipher_scalar, nonce) = poseidon_encryption.encrypt_scalar(&message_scalar, &symmetric_key);

    let mut poseidon_circuit = PoseidonCircuit::new();
    poseidon_circuit.setup_parameter();

    let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
    let prover_key = poseidon_circuit.prover_key.clone().unwrap();
    let verifier_data = poseidon_circuit.verifier_data.clone().unwrap();

    let label = b"poseidon-cipher";

    poseidon_circuit.set_input(symmetric_key, nonce, &message_scalar[..], &cipher_scalar[..]);
    let proof = poseidon_circuit.prove(&public_parameter, &prover_key, label)?;

    let mut public_input = vec![];
    cipher_scalar.iter().for_each(|c| {
      public_input.push(PublicInputValue::from(*c));
    });

    PoseidonCircuit::verify(&public_parameter, &verifier_data, &proof, &public_input, label)?;
    poseidon_circuit.export_parameter();

    Ok(())
  }

  #[test]
  fn gadget_test_with_load_parameter() -> Result<(), PlonkError> {
    // Generate a secret and a public key for Bob
    let bob_secret = JubJubScalar::random(&mut OsRng);

    // Generate a secret and a public key for Alice
    let alice_secret = JubJubScalar::random(&mut OsRng);
    let alice_public = GENERATOR_EXTENDED * alice_secret;

    // Generate a shared secret
    let symmetric_key = dhke(&bob_secret, &alice_public);

    // Generate a secret message
    let message = "sample message".to_string();

    // Perform the encryption
    let poseidon_encryption = PoseidonEncryption::new();
    let message_scalar = poseidon_encryption.get_message_bls_scalar_vector(message.as_bytes());

    let (cipher_scalar, nonce) = poseidon_encryption.encrypt_scalar(&message_scalar, &symmetric_key);

    let mut poseidon_circuit = PoseidonCircuit::new();
    poseidon_circuit.import_parameter();

    let public_parameter = poseidon_circuit.public_parameter.clone().unwrap();
    let prover_key = poseidon_circuit.prover_key.clone().unwrap();
    let verifier_data = poseidon_circuit.verifier_data.clone().unwrap();

    let label = b"poseidon-cipher";

    poseidon_circuit.set_input(symmetric_key, nonce, &message_scalar[..], &cipher_scalar[..]);

    poseidon_circuit.prove(&public_parameter, &prover_key, label)?;
    let proof = poseidon_circuit.prove(&public_parameter, &prover_key, label)?;

    let mut public_input = vec![];
    cipher_scalar.iter().for_each(|c| {
      public_input.push(PublicInputValue::from(*c));
    });

    PoseidonCircuit::verify(&public_parameter, &verifier_data, &proof, &public_input, label)?;

    Ok(())
  }
}
