#pragma once
#include "barretenberg/common/wasm_export.hpp"
#include "barretenberg/ecc/curves/bn254/fr.hpp"

extern "C" {

using namespace barretenberg;

WASM_EXPORT const char * pedersen___init();

WASM_EXPORT const char * pedersen___compress_fields(fr::in_buf left, fr::in_buf right, fr::out_buf result);
WASM_EXPORT const char * pedersen___plookup_compress_fields(fr::in_buf left, fr::in_buf right, fr::out_buf result);

WASM_EXPORT const char * pedersen___compress(fr::vec_in_buf inputs_buffer, fr::out_buf output);
WASM_EXPORT const char * pedersen___plookup_compress(fr::vec_in_buf inputs_buffer, fr::out_buf output);

WASM_EXPORT const char * pedersen___compress_with_hash_index(fr::vec_in_buf inputs_buffer,
                                                     uint32_t const* hash_index,
                                                     fr::out_buf output);

WASM_EXPORT const char * pedersen___commit(fr::vec_in_buf inputs_buffer, fr::out_buf output);
WASM_EXPORT const char * pedersen___plookup_commit(fr::vec_in_buf inputs_buffer, fr::out_buf output);
WASM_EXPORT const char * pedersen___plookup_commit_with_hash_index(fr::vec_in_buf inputs_buffer,
                                                           uint32_t const* hash_index,
                                                           fr::out_buf output);

WASM_EXPORT const char * pedersen___buffer_to_field(uint8_t const* data, fr::out_buf r);
}