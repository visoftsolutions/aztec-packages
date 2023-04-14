import { AztecNode } from '@aztec/aztec-node';
import { AztecRPCServer, ContractDeployer, Fr, TxStatus } from '@aztec/aztec.js';
import { EthereumRpc } from '@aztec/ethereum.js/eth_rpc';
import { WalletProvider } from '@aztec/ethereum.js/provider';
import { EthAddress, createDebugLogger } from '@aztec/foundation';
import { ContractAbi } from '@aztec/noir-contracts';
import { TestContractAbi } from '@aztec/noir-contracts/examples';
import times from 'lodash.times';
import { createAztecNode } from './create_aztec_node.js';
import { createAztecRpcServer } from './create_aztec_rpc_client.js';
import { createProvider, deployRollupContract, deployUnverifiedDataEmitterContract } from './deploy_l1_contracts.js';

const { ETHEREUM_HOST = 'http://localhost:8545' } = process.env;
const MNEMONIC = 'test test test test test test test test test test test junk';

const logger = createDebugLogger('aztec:e2e_block_building');
describe('e2e_block_building', () => {
  let provider: WalletProvider;
  let node: AztecNode;
  let aztecRpcServer: AztecRPCServer;
  let rollupAddress: EthAddress;
  let unverifiedDataEmitterAddress: EthAddress;

  const abi = TestContractAbi as ContractAbi;

  beforeEach(async () => {
    provider = createProvider(ETHEREUM_HOST, MNEMONIC, 1);
    const ethRpc = new EthereumRpc(provider);
    logger('Deploying contracts...');
    rollupAddress = await deployRollupContract(provider, ethRpc);
    unverifiedDataEmitterAddress = await deployUnverifiedDataEmitterContract(provider, ethRpc);
    logger('Deployed contracts...');
  });

  beforeEach(async () => {
    node = await createAztecNode(
      rollupAddress,
      unverifiedDataEmitterAddress,
      ETHEREUM_HOST,
      provider.getPrivateKey(0)!,
    );
    aztecRpcServer = await createAztecRpcServer(1, node);
  }, 10_000);

  afterEach(async () => {
    await node.stop();
    await aztecRpcServer.stop();
  });

  it('should assemble a block with multiple txs', async () => {
    // Assemble 10 contract deployment txs
    // We need to create them sequentially since we cannot have parallel calls to a circuit
    const deployer = new ContractDeployer(abi, aztecRpcServer);
    const methods = times(10, () => deployer.deploy());

    for (const i in methods) {
      await methods[i].create({ contractAddressSalt: new Fr(BigInt(i + 1)) });
    }

    // Send them simultaneously to be picked up by the sequencer
    const txs = await Promise.all(methods.map(method => method.send()));
    logger(`Txs sent with hashes: `);
    for (const tx of txs) logger(` ${await tx.getTxHash()}`);

    // Await txs to be mined and assert they are all mined on the same block
    await Promise.all(txs.map(tx => tx.isMined()));
    const receipts = await Promise.all(txs.map(tx => tx.getReceipt()));
    expect(receipts.map(r => r.status)).toEqual(times(10, () => TxStatus.MINED));
    expect(receipts.map(r => r.blockNumber)).toEqual(times(10, () => receipts[0].blockNumber));

    // Assert all contracts got deployed
    const areDeployed = await Promise.all(receipts.map(r => aztecRpcServer.isContractDeployed(r.contractAddress!)));
    expect(areDeployed).toEqual(times(10, () => true));
  }, 60_000);
});