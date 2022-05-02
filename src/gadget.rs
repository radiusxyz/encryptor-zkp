use dusk_hades::GadgetStrategy;
use encryptor::PoseidonEncryption;

use dusk_plonk::prelude::*;

/// Returns the initial state of the encryption within a composer circuit
pub fn initial_state_circuit(composer: &mut TurboComposer, ks0: Witness, ks1: Witness, nonce: Witness) -> [Witness; dusk_hades::WIDTH] {
  let domain = BlsScalar::from_raw([0x100000000u64, 0, 0, 0]);
  let domain = composer.append_constant(domain);

  let length = BlsScalar::from_raw([PoseidonEncryption::capacity() as u64, 0, 0, 0]);
  let length = composer.append_constant(length);

  [domain, length, ks0, ks1, nonce]
}

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform the encryption of the message.
/// The returned set of variables is the cipher text
pub fn encrypt(composer: &mut TurboComposer, shared_secret: &WitnessPoint, nonce: Witness, message: &[Witness]) -> [Witness; PoseidonEncryption::cipher_size()] {
  let zero = TurboComposer::constant_zero();

  let ks0 = *shared_secret.x();
  let ks1 = *shared_secret.y();

  let mut cipher = [zero; PoseidonEncryption::cipher_size()];
  let mut state = initial_state_circuit(composer, ks0, ks1, nonce);
  let count = (PoseidonEncryption::capacity() + 3) / 4;

  (0..count).for_each(|i| {
    GadgetStrategy::gadget(composer, &mut state);

    (0..4).for_each(|j| {
      if 4 * i + j < PoseidonEncryption::capacity() {
        let x = if 4 * i + j < message.len() { message[4 * i + j] } else { zero };
        let constraint = Constraint::new().left(1).a(state[j + 1]).right(1).b(x);

        state[j + 1] = composer.gate_add(constraint);

        cipher[4 * i + j] = state[j + 1];
      }
    });
  });

  GadgetStrategy::gadget(composer, &mut state);
  cipher[PoseidonEncryption::capacity()] = state[1];

  cipher
}
