import { ContractData, L2Block } from '@aztec/l2-block';
import {
  Fr,
  KERNEL_NEW_CONTRACTS_LENGTH,
  KERNEL_NEW_COMMITMENTS_LENGTH,
  KERNEL_NEW_NULLIFIERS_LENGTH,
  AppendOnlyTreeSnapshot,
  NewContractData,
  AztecAddress,
} from '@aztec/circuits.js';
import { MerkleTreeId, MerkleTreeOperations } from '@aztec/world-state';
import { Tx } from '@aztec/tx';
import { createDebugLogger } from '@aztec/foundation';

const mapContractData = (n: NewContractData) => {
  const contractData = new ContractData(AztecAddress.fromBuffer(n.contractAddress.toBuffer()), n.portalContractAddress);
  return contractData;
};

export class BlockBuilder {
  private dataTreeLeaves: Buffer[] = [];
  private nullifierTreeLeaves: Buffer[] = [];
  private contractTreeLeaves: Buffer[] = [];

  constructor(
    private db: MerkleTreeOperations,
    private nextBlockNum: number,
    private tx: Tx,
    private log = createDebugLogger('aztec:block_builder'),
  ) {
    this.dataTreeLeaves = tx.data.end.newCommitments.map((x: Fr) => x.toBuffer());
    this.nullifierTreeLeaves = tx.data.end.newNullifiers.map((x: Fr) => x.toBuffer());
    this.contractTreeLeaves = tx.data.end.newContracts.map((x: NewContractData) => x.functionTreeRoot.toBuffer());
  }

  public async buildL2Block() {
    const startPrivateDataTreeSnapshot = await this.getTreeSnapshot(MerkleTreeId.DATA_TREE);
    const startNullifierTreeSnapshot = await this.getTreeSnapshot(MerkleTreeId.NULLIFIER_TREE);
    const startContractTreeSnapshot = await this.getTreeSnapshot(MerkleTreeId.CONTRACT_TREE);
    const startTreeOfHistoricPrivateDataTreeRootsSnapshot = await this.getTreeSnapshot(
      MerkleTreeId.DATA_TREE_ROOTS_TREE,
    );
    const startTreeOfHistoricContractTreeRootsSnapshot = await this.getTreeSnapshot(
      MerkleTreeId.CONTRACT_TREE_ROOTS_TREE,
    );

    await this.updateTrees();

    const endPrivateDataTreeSnapshot = await this.getTreeSnapshot(MerkleTreeId.DATA_TREE);
    const endNullifierTreeSnapshot = await this.getTreeSnapshot(MerkleTreeId.NULLIFIER_TREE);
    const endContractTreeSnapshot = await this.getTreeSnapshot(MerkleTreeId.CONTRACT_TREE);
    const endTreeOfHistoricPrivateDataTreeRootsSnapshot = await this.getTreeSnapshot(MerkleTreeId.DATA_TREE_ROOTS_TREE);
    const endTreeOfHistoricContractTreeRootsSnapshot = await this.getTreeSnapshot(
      MerkleTreeId.CONTRACT_TREE_ROOTS_TREE,
    );
    this.log(`contract address ${this.tx.data.end.newContracts[0].contractAddress.toString()}`);

    const l2block = L2Block.fromFields({
      number: this.nextBlockNum,
      startPrivateDataTreeSnapshot,
      endPrivateDataTreeSnapshot,
      startNullifierTreeSnapshot,
      endNullifierTreeSnapshot,
      startContractTreeSnapshot,
      endContractTreeSnapshot,
      startTreeOfHistoricPrivateDataTreeRootsSnapshot,
      endTreeOfHistoricPrivateDataTreeRootsSnapshot,
      startTreeOfHistoricContractTreeRootsSnapshot,
      endTreeOfHistoricContractTreeRootsSnapshot,
      newCommitments: this.dataTreeLeaves.map(b => Fr.fromBuffer(b)),
      newNullifiers: this.nullifierTreeLeaves.map(b => Fr.fromBuffer(b)),
      newContracts: this.contractTreeLeaves.map(b => Fr.fromBuffer(b)),
      newContractData: this.tx.data.end.newContracts.map(mapContractData),
    });
    return l2block;
  }

  private async getTreeSnapshot(id: MerkleTreeId): Promise<AppendOnlyTreeSnapshot> {
    const treeInfo = await this.db.getTreeInfo(id);
    return new AppendOnlyTreeSnapshot(Fr.fromBuffer(treeInfo.root), Number(treeInfo.size));
  }

  private async updateTrees() {
    for (let i = 0; i < KERNEL_NEW_COMMITMENTS_LENGTH; i++) {
      await this.db.appendLeaves(MerkleTreeId.DATA_TREE, [this.dataTreeLeaves[i]]);
    }
    for (let i = 0; i < KERNEL_NEW_NULLIFIERS_LENGTH; i++) {
      await this.db.appendLeaves(MerkleTreeId.NULLIFIER_TREE, [this.nullifierTreeLeaves[i]]);
    }
    for (let i = 0; i < KERNEL_NEW_CONTRACTS_LENGTH; i++) {
      await this.db.appendLeaves(MerkleTreeId.CONTRACT_TREE, [this.contractTreeLeaves[i]]);
    }
    const newDataTreeInfo = await this.getTreeSnapshot(MerkleTreeId.DATA_TREE);
    const newContractsTreeInfo = await this.getTreeSnapshot(MerkleTreeId.CONTRACT_TREE);
    await this.db.appendLeaves(MerkleTreeId.CONTRACT_TREE_ROOTS_TREE, [newContractsTreeInfo.root.toBuffer()]);
    await this.db.appendLeaves(MerkleTreeId.DATA_TREE_ROOTS_TREE, [newDataTreeInfo.root.toBuffer()]);
  }

  // private async getCurrentTreeRoots() {
  //   return await Promise.all([
  //     this.getTreeRoot(MerkleTreeId.NULLIFIER_TREE),
  //     this.getTreeRoot(MerkleTreeId.CONTRACT_TREE),
  //   ]);
  // }

  // private getTxContext(tx: Tx) {
  //   if (tx.data.end.newContracts.length !== 1) {
  //     throw new Error(`Only txs that deploy exactly one contract are supported for now`);
  //   }
  //   const [newContract] = tx.data.end.newContracts;

  //   return new TxContext(
  //     false, // isFeePayment
  //     false, // isRebatePayment
  //     true, // isContractDeployment
  //     new ContractDeploymentData(
  //       TODO_FR, // TODO: constructorVkHash
  //       newContract.functionTreeRoot,
  //       TODO_FR, // TODO: contractAddressSalt
  //       newContract.portalContractAddress,
  //     ),
  //   );
  // }

  // private getKernelDataFor(tx: Tx) {
  //   return new PreviousKernelData(
  //     tx.data,
  //     TODO, // TODO: proof, isn't this the tx.data.end.aggregationObject?,
  //     TODO, // TODO: vk
  //     TODO_NUM, // TODO: vkIndex
  //     Array(VK_TREE_HEIGHT).fill(TODO_FR), // TODO: vkSiblingPath
  //   );
  // }

  // private getConstantBaseRollupData(): Promise<ConstantBaseRollupData> {
  //   throw new Error('Unimplemented');
  // }

  // private async getBaseRollupInputsFor(tx: Tx) {
  //   return BaseRollupInputs.from({
  //     proverId: TODO_FR,
  //     constants: await this.getConstantBaseRollupData(),
  //   } as any); // TODO: Carry on...
  // }
}
