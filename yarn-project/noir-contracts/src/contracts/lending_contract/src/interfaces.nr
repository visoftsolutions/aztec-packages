use dep::aztec::context::{
    PrivateContext,
    PublicContext
};

use crate::asset::Asset;
use dep::protocol_types::constants::RETURN_VALUES_LENGTH;
use dep::aztec::selector::compute_selector;

struct PriceFeed {
  address: Field,
}

impl PriceFeed {
  pub fn at(address: Field) -> Self {
    Self { address }
  }

  pub fn get_price(self: Self, context: PublicContext) -> u120 {
    let return_values = context.call_public_function(
      self.address, 
      compute_selector("get_price(Field)"),
      [0]
    );

    return_values[0] as u120
  }
}

struct Token {
  address: Field,
}

impl Token {
  pub fn at(address: Field) -> Self {
    Self { address }
  }

  pub fn transfer_public(self: Self, context: PublicContext, from: Field, to: Field, amount: Field, nonce: Field) {
    context.call_public_function(
      self.address,
      compute_selector("transfer_public((Field),(Field),Field,Field)"),
      [from, to, amount, nonce]
    );
  }

  pub fn mint_public(self: Self, context: PublicContext, to: Field, amount: Field) {
    context.call_public_function(
      self.address,
      compute_selector("mint_public((Field),Field)"),
      [to, amount]
    );
  }

  pub fn burn_public(self: Self, context: PublicContext, from: Field, amount: Field, nonce: Field) {
    context.call_public_function(
      self.address,
      compute_selector("burn_public((Field),Field,Field)"),
      [from, amount, nonce]
    );
  }

  // Private
  pub fn unshield(self: Self, context: &mut PrivateContext, from: Field, to: Field, amount: Field, nonce: Field) -> [Field; RETURN_VALUES_LENGTH] {
    context.call_private_function(
      self.address,
      compute_selector("unshield((Field),(Field),Field,Field)"),
      [from, to, amount, nonce]
    )
  }

  pub fn burn(self: Self, context: &mut PrivateContext, from: Field, amount: Field, nonce: Field) -> [Field; RETURN_VALUES_LENGTH] {
    context.call_private_function(
      self.address,
      compute_selector("burn((Field),Field,Field)"),
      [from, amount, nonce]
    )
  }
}

struct Lending {
  address: Field,
}

impl Lending {
  pub fn at(address: Field) -> Self {
    Self { address }
  }

  pub fn update_accumulator(self: Self, context: PublicContext) -> Asset {
    let return_values = context.call_public_function_no_args(
      self.address,
      compute_selector("update_accumulator()"),
    );

    Asset {
      interest_accumulator: return_values[0] as u120,
      last_updated_ts: return_values[1] as u120,
      loan_to_value: return_values[2] as u120,
      oracle_address: return_values[3],
    }
  }
}
