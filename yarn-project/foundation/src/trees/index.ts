/**
 * A leaf of an indexed merkle tree.
 */
export interface IndexedTreeLeaf {
  /**
   * Returns key of the leaf. It's used for indexing.
   */
  getKey(): bigint;
  /**
   * Serializes the leaf into a buffer.
   */
  toBuffer(): Buffer;
  /**
   * Returns true if the leaf is empty.
   */
  isEmpty(): boolean;
}

/**
 * Preimage of an indexed merkle tree leaf.
 */
export interface IndexedTreeLeafPreimage {
  /**
   * Returns key of the leaf corresponding to this preimage.
   */
  getKey(): bigint;
  /**
   * Returns the key of the next leaf.
   */
  getNextKey(): bigint;
  /**
   * Returns the index of the next leaf.
   */
  getNextIndex(): bigint;

  /**
   * Returns the preimage as a leaf.
   */
  asLeaf(): IndexedTreeLeaf;
  /**
   * Serializes the preimage into a buffer.
   */
  toBuffer(): Buffer;
  /**
   * Serializes the preimage to an array of buffers for hashing.
   */
  toHashInputs(): Buffer[];
}
