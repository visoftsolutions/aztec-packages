/**
 * Defines the possible Merkle tree IDs.
 */
export enum MerkleTreeId {
  CONTRACT_TREE = 0,
  NULLIFIER_TREE = 1,
  NOTE_HASH_TREE = 2,
  PUBLIC_DATA_TREE = 3,
  L1_TO_L2_MESSAGES_TREE = 4,
  ARCHIVE = 5,
}

export const merkleTreeIds = () => {
  return Object.values(MerkleTreeId).filter((v): v is MerkleTreeId => !isNaN(Number(v)));
};
