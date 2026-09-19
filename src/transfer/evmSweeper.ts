import { Contract, JsonRpcProvider, Transaction, TransactionRequest, Wallet, getAddress, isAddress } from 'ethers';
import { EvmAdapter, EvmChainConfig, scaleUnits } from '../chains/evm';
import { AssetBalance } from '../chains/types';
import { PriceService } from '../pricing/priceService';
import {
  ExecutedTransfer,
  FailedTransfer,
  MIN_VALUE_THRESHOLD_USD,
  PlannedTransfer,
  SweepCandidate,
  SweepOptions,
  SweepPlan,
  SweepResult,
  classifyAssets,
  withBuffer,
} from './types';

const ERC20_ABI = [
  'function transfer(address to, uint256 amount) returns (bool)',
  'function balanceOf(address owner) view returns (uint256)',
];

/** Gas a plain value transfer to an EOA costs, fixed by the protocol. */
const NATIVE_TRANSFER_GAS = 21_000n;

/** Used when a node refuses to estimate an ERC-20 transfer (e.g. a rate-limited public RPC). */
const FALLBACK_TOKEN_GAS = 100_000n;

/** Headroom over the estimate, covering gas price drift between planning and sending. */
const DEFAULT_GAS_BUFFER_PERCENT = 25;

/** Predeploy address of the OP-stack L1 gas price oracle, identical on every OP chain. */
const L1_GAS_PRICE_ORACLE = '0x420000000000000000000000000000000000000F';
const L1_ORACLE_ABI = ['function getL1Fee(bytes data) view returns (uint256)'];

export interface EvmSweepOptions extends SweepOptions {
  rpcUrl?: string;
  /** Percent of headroom added to fee estimates. Defaults to 25. */
  gasBufferPercent?: number;
}

/**
 * Moves every asset above a value threshold out of one EVM wallet.
 *
 * Unlike the Solana mover, EVM has no way to batch unrelated transfers into a
 * single transaction from an EOA, so a sweep is N token transactions followed
 * by the native one. The native transfer goes last and is sized against a
 * freshly read balance, because the gas the token transfers actually burn is
 * never exactly what was estimated.
 */
export class EvmSweeper {
  readonly config: EvmChainConfig;

  private readonly provider: JsonRpcProvider;
  private readonly wallet: Wallet;
  private readonly reader: EvmAdapter;
  private readonly prices: PriceService;
  private readonly minValueUsd: number;
  private readonly includeUnpriced: boolean;
  private readonly gasBufferPercent: number;

  constructor(privateKey: string, config: EvmChainConfig, options: EvmSweepOptions = {}) {
    this.config = config;
    this.minValueUsd = options.minValueUsd ?? MIN_VALUE_THRESHOLD_USD;
    this.includeUnpriced = options.includeUnpriced ?? false;
    this.gasBufferPercent = options.gasBufferPercent ?? DEFAULT_GAS_BUFFER_PERCENT;

    const rpcUrl = options.rpcUrl || config.defaultRpcUrl;
    this.provider = new JsonRpcProvider(rpcUrl);
    this.wallet = new Wallet(normalizePrivateKey(privateKey), this.provider);
    this.reader = new EvmAdapter(config, rpcUrl);
    this.prices = PriceService.getInstance();
  }

  /** Address the supplied key controls. */
  get address(): string {
    return this.wallet.address;
  }

  /**
   * Work out exactly what a sweep would move, without signing anything.
   *
   * Reading is done through the watch-only adapter, so token coverage here is
   * the same registry the portfolio viewer uses.
   */
  async planSweep(destination: string, ): Promise<SweepPlan> {
    const to = normalizeEvmDestination(destination, this.address);
    await this.assertCorrectChain();

    const balances = await this.reader.getBalances(this.address);
    const valued = await this.prices.priceAssets(balances);
    const candidates = valued.map(toCandidate);

    const { worthMoving, skipped } = classifyAssets(candidates, this.minValueUsd, this.includeUnpriced);
    const tokens = worthMoving.filter((asset) => !asset.isNative);
    const native = candidates.find((asset) => asset.isNative);

    const warnings: string[] = [];
    if (await this.isContract(to)) {
      warnings.push(
        `Destination ${to} is a contract, not a regular wallet. Funds sent to a contract that does not handle them are unrecoverable.`
      );
    }

    // Price the whole sweep before deciding how much native asset can leave.
    const { maxFeePerGas, maxPriorityFeePerGas } = await this.feeParameters();
    let totalGas = 0n;
    const tokenGas = new Map<string, bigint>();

    for (const token of tokens) {
      const gas = await this.estimateTokenGas(token, to);
      tokenGas.set(token.contract!, gas);
      totalGas += gas;
    }

    const nativeHeld = native?.rawAmount ?? 0n;
    const sendingNative = nativeHeld > 0n;
    if (sendingNative) totalGas += NATIVE_TRANSFER_GAS;

    let feeReserveRaw = withBuffer(totalGas * maxFeePerGas, this.gasBufferPercent);
    if (this.config.isOpStack) {
      feeReserveRaw += await this.estimateL1DataFee(to, tokens.length + (sendingNative ? 1 : 0));
    }

    if (tokens.length > 0 && nativeHeld < feeReserveRaw) {
      throw new Error(
        `Not enough ${this.config.nativeSymbol} to pay for ${tokens.length} token transfer(s) on ${this.config.displayName}. ` +
          `Need about ${scaleUnits(feeReserveRaw, 18).toFixed(6)}, have ${scaleUnits(nativeHeld, 18).toFixed(6)}.`
      );
    }

    const transfers: PlannedTransfer[] = tokens.map((asset) => ({
      asset,
      rawAmount: asset.rawAmount,
      amount: asset.amount,
      valueUsd: asset.valueUsd,
    }));

    if (native) {
      const netRaw = nativeHeld > feeReserveRaw ? nativeHeld - feeReserveRaw : 0n;
      const netAmount = scaleUnits(netRaw, native.decimals);
      const netValue = native.priceUsd === null ? null : netAmount * native.priceUsd;

      if (netRaw <= 0n) {
        skipped.push({ asset: native, reason: 'entire balance is needed to cover fees' });
      } else if (netValue !== null && netValue < this.minValueUsd) {
        skipped.push({
          asset: native,
          reason: `only $${netValue.toFixed(2)} would be left after fees, below the $${this.minValueUsd} threshold`,
        });
      } else if (netValue === null && !this.includeUnpriced) {
        skipped.push({ asset: native, reason: 'no price source resolved it; pass --include-unpriced to move it anyway' });
      } else {
        transfers.push({ asset: native, rawAmount: netRaw, amount: netAmount, valueUsd: netValue });
      }
    }

    if (maxPriorityFeePerGas === null) {
      warnings.push(`${this.config.displayName} RPC reported no EIP-1559 fee data; falling back to a legacy gas price.`);
    }
    if (transfers.some((transfer) => transfer.valueUsd === null)) {
      warnings.push('Some assets in this sweep are unpriced; their USD value is unknown and excluded from the total.');
    }
    if (tokens.length > 0) {
      warnings.push(
        `EVM cannot batch these: this sweep broadcasts ${transfers.length} separate transactions. ` +
          'If one fails the others still stand.'
      );
    }

    return {
      chain: this.config.chain,
      source: this.address,
      destination: to,
      nativeSymbol: this.config.nativeSymbol,
      transfers,
      skipped,
      feeReserveRaw,
      feeReserve: scaleUnits(feeReserveRaw, 18),
      transactionCount: transfers.length,
      totalValueUsd: transfers.reduce((sum, transfer) => sum + (transfer.valueUsd ?? 0), 0),
      warnings,
    };
  }

  /**
   * Broadcast a plan.
   *
   * Tokens go first and the native asset last, so the gas the token transfers
   * burn is already reflected in the balance the native transfer is sized
   * against. One failed token transfer does not abort the rest.
   */
  async executeSweep(plan: SweepPlan): Promise<SweepResult> {
    const executed: ExecutedTransfer[] = [];
    const failed: FailedTransfer[] = [];

    for (const transfer of plan.transfers.filter((item) => !item.asset.isNative)) {
      try {
        const contract = new Contract(transfer.asset.contract!, ERC20_ABI, this.wallet);
        const tx = await contract.transfer(plan.destination, transfer.rawAmount);
        await tx.wait(1);
        executed.push(this.record(transfer.asset.symbol, transfer, tx.hash));
      } catch (error) {
        failed.push({ symbol: transfer.asset.symbol, error: describe(error) });
      }
    }

    const nativeTransfer = plan.transfers.find((item) => item.asset.isNative);
    if (nativeTransfer) {
      try {
        const sent = await this.sweepNative(plan.destination, nativeTransfer);
        executed.push(sent);
      } catch (error) {
        failed.push({ symbol: this.config.nativeSymbol, error: describe(error) });
      }
    }

    return {
      success: failed.length === 0 && executed.length > 0,
      chain: this.config.chain,
      executed,
      failed,
      totalValueUsd: executed.reduce((sum, item) => sum + (item.valueUsd ?? 0), 0),
    };
  }

  /**
   * Send the native balance minus the exact cost of sending it.
   *
   * The balance is re-read here rather than taken from the plan: token
   * transfers have already spent gas, and the plan's figure is stale.
   */
  private async sweepNative(destination: string, planned: PlannedTransfer): Promise<ExecutedTransfer> {
    const balance = await this.provider.getBalance(this.address);
    const { maxFeePerGas, maxPriorityFeePerGas } = await this.feeParameters();

    let reserve = NATIVE_TRANSFER_GAS * maxFeePerGas;
    if (this.config.isOpStack) {
      reserve += await this.estimateL1DataFee(destination, 1);
    }

    const request = buildNativeTransfer(destination, balance, reserve, maxFeePerGas, maxPriorityFeePerGas);

    const tx = await this.wallet.sendTransaction(request);
    await tx.wait(1);

    const amount = scaleUnits(request.value as bigint, 18);
    const price = planned.asset.priceUsd;
    return {
      symbol: this.config.nativeSymbol,
      amount,
      valueUsd: price === null ? null : amount * price,
      txHash: tx.hash,
      explorerUrl: `${this.config.explorerUrl}/tx/${tx.hash}`,
    };
  }

  private record(symbol: string, transfer: PlannedTransfer, hash: string): ExecutedTransfer {
    return {
      symbol,
      contract: transfer.asset.contract,
      amount: transfer.amount,
      valueUsd: transfer.valueUsd,
      txHash: hash,
      explorerUrl: `${this.config.explorerUrl}/tx/${hash}`,
    };
  }

  /**
   * Reject an RPC that is not the chain we think it is.
   *
   * Signing against the wrong chain id at best fails and at worst sends funds
   * somewhere the operator did not intend.
   */
  private async assertCorrectChain(): Promise<void> {
    const network = await this.provider.getNetwork();
    if (network.chainId !== BigInt(this.config.chainId)) {
      throw new Error(
        `RPC endpoint reports chain id ${network.chainId}, but ${this.config.displayName} is ${this.config.chainId}. ` +
          'Refusing to sign against the wrong network.'
      );
    }
  }

  private async isContract(address: string): Promise<boolean> {
    try {
      return (await this.provider.getCode(address)) !== '0x';
    } catch {
      return false;
    }
  }

  /**
   * Resolve the gas price to budget against.
   *
   * `maxPriorityFeePerGas` comes back null on chains or endpoints without
   * EIP-1559, which tells the caller to send a legacy transaction.
   */
  private async feeParameters(): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint | null }> {
    const feeData = await this.provider.getFeeData();
    const maxFeePerGas = feeData.maxFeePerGas ?? feeData.gasPrice;

    if (maxFeePerGas === null || maxFeePerGas === undefined) {
      throw new Error(`${this.config.displayName} RPC returned no gas price; cannot size a fee reserve.`);
    }

    return {
      maxFeePerGas,
      maxPriorityFeePerGas: feeData.maxFeePerGas === null ? null : feeData.maxPriorityFeePerGas,
    };
  }

  private async estimateTokenGas(token: SweepCandidate, destination: string): Promise<bigint> {
    try {
      const contract = new Contract(token.contract!, ERC20_ABI, this.wallet);
      const gas = await contract.transfer.estimateGas(destination, token.rawAmount);
      // The estimate reflects current state; a destination holding none of this
      // token yet writes a fresh storage slot, so keep headroom either way.
      return withBuffer(gas, 20);
    } catch {
      return FALLBACK_TOKEN_GAS;
    }
  }

  /**
   * L1 data fee an OP-stack chain charges on top of L2 gas.
   *
   * It is derived from the serialized transaction, so it is estimated from a
   * representative transfer and multiplied by the number of transactions. A
   * signature adds ~68 bytes that the unsigned form does not carry, hence the
   * headroom.
   */
  private async estimateL1DataFee(destination: string, transactionCount: number): Promise<bigint> {
    if (transactionCount <= 0) return 0n;

    try {
      const oracle = new Contract(L1_GAS_PRICE_ORACLE, L1_ORACLE_ABI, this.provider);
      const sample = Transaction.from({
        to: destination,
        value: 1n,
        gasLimit: NATIVE_TRANSFER_GAS,
        chainId: this.config.chainId,
        nonce: 0,
      }).unsignedSerialized;

      const perTransaction: bigint = await oracle.getL1Fee(sample);
      return withBuffer(perTransaction * BigInt(transactionCount), 50);
    } catch {
      // Oracle unreachable: the percentage buffer on the L2 fee is all we have.
      return 0n;
    }
  }
}

function toCandidate(asset: AssetBalance): SweepCandidate {
  return {
    symbol: asset.symbol,
    name: asset.name,
    contract: asset.contract,
    decimals: asset.decimals,
    rawAmount: BigInt(asset.rawAmount),
    amount: asset.amount,
    priceUsd: asset.priceUsd,
    valueUsd: asset.valueUsd,
    isNative: asset.isNative,
  };
}

/**
 * Size the final native transfer: the whole balance, less the cost of sending it.
 *
 * Budgeting against `maxFeePerGas` rather than the expected effective price
 * means the transaction is always payable; the unspent difference stays behind
 * as a few wei of dust, which is the right way round to be wrong.
 */
export function buildNativeTransfer(
  destination: string,
  balance: bigint,
  reserve: bigint,
  maxFeePerGas: bigint,
  maxPriorityFeePerGas: bigint | null
): TransactionRequest {
  const value = balance - reserve;
  if (value <= 0n) {
    throw new Error(
      `Nothing left to sweep after fees: balance ${scaleUnits(balance, 18).toFixed(6)}, ` +
        `fee reserve ${scaleUnits(reserve, 18).toFixed(6)}.`
    );
  }

  return {
    to: destination,
    value,
    gasLimit: NATIVE_TRANSFER_GAS,
    // A chain or endpoint without EIP-1559 needs a legacy gas price instead.
    ...(maxPriorityFeePerGas === null ? { gasPrice: maxFeePerGas } : { maxFeePerGas, maxPriorityFeePerGas }),
  };
}

/**
 * Check a destination and return it checksummed.
 *
 * `getAddress` rejects a mixed-case address whose EIP-55 checksum does not
 * match, which is the cheapest available guard against a mistyped destination.
 */
export function normalizeEvmDestination(destination: string, source: string): string {
  const value = destination.trim();
  if (!isAddress(value)) {
    throw new Error(`Not a valid EVM address: ${destination}`);
  }

  const checksummed = getAddress(value);
  if (checksummed.toLowerCase() === source.toLowerCase()) {
    throw new Error('Destination is the source wallet; nothing to do.');
  }
  return checksummed;
}

/** Accept a key with or without the 0x prefix; reject anything that is not 32 bytes. */
export function normalizePrivateKey(privateKey: string): string {
  const value = privateKey.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('Expected a 32-byte hex private key (64 hex characters, optionally 0x-prefixed).');
  }
  return `0x${value}`;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : 'Unknown error';
}
