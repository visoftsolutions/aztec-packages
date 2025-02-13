/* Autogenerated file, do not edit! */

/* eslint-disable */

export type FixedLengthArray<T, L extends number> = L extends 0 ? never[] : T[] & { length: L };

export type Field = string;
export type u32 = string;

export interface AggregationObject {}

export interface AppendOnlyTreeSnapshot {
  root: Field;
  next_available_leaf_index: u32;
}

export interface GlobalVariables {
  chain_id: Field;
  version: Field;
  block_number: Field;
  timestamp: Field;
}

export interface ConstantRollupData {
  archive_snapshot: AppendOnlyTreeSnapshot;
  private_kernel_vk_tree_root: Field;
  public_kernel_vk_tree_root: Field;
  base_rollup_vk_hash: Field;
  merge_rollup_vk_hash: Field;
  global_variables: GlobalVariables;
}

export interface BaseOrMergeRollupPublicInputs {
  rollup_type: u32;
  rollup_subtree_height: Field;
  end_aggregation_object: AggregationObject;
  constants: ConstantRollupData;
  start_note_hash_tree_snapshot: AppendOnlyTreeSnapshot;
  end_note_hash_tree_snapshot: AppendOnlyTreeSnapshot;
  start_nullifier_tree_snapshot: AppendOnlyTreeSnapshot;
  end_nullifier_tree_snapshot: AppendOnlyTreeSnapshot;
  start_contract_tree_snapshot: AppendOnlyTreeSnapshot;
  end_contract_tree_snapshot: AppendOnlyTreeSnapshot;
  start_public_data_tree_root: Field;
  end_public_data_tree_root: Field;
  calldata_hash: FixedLengthArray<Field, 2>;
}

export interface Proof {}

export interface VerificationKey {}

export interface VKMembershipWitness {
  leaf_index: Field;
  sibling_path: FixedLengthArray<Field, 8>;
}

export interface PreviousRollupData {
  base_or_merge_rollup_public_inputs: BaseOrMergeRollupPublicInputs;
  proof: Proof;
  vk: VerificationKey;
  vk_index: u32;
  vk_sibling_path: VKMembershipWitness;
}

export interface MergeRollupInputs {
  previous_rollup_data: FixedLengthArray<PreviousRollupData, 2>;
}

export type ReturnType = BaseOrMergeRollupPublicInputs;

export interface InputType {
  inputs: MergeRollupInputs;
}
