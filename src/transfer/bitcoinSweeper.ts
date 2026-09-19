import axios, { AxiosInstance } from 'axios';
import { BIP32Interface } from 'bip32';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import { scaleUnits } from '../chains/evm';
import { ChainId } from '../chains/types';
import { PriceService } from '../pricing/priceService';
import { UTXO_PURPOSES, UtxoNetworkConfig, UtxoScriptType, utxoNetwork } from '../chains/utxoNetworks';
import {
  DEFAULT_GAP_LIMIT,
  addressForScriptType,
  deriveBitcoinKey,
  mnemonicToSeed,
  rootFromSeed,
} from './hdWallet';
import {
  ExecutedTransfer,
  MIN_VALUE_THRESHOLD_USD,
  SweepCandidate,
  SweepOptions,
  SweepPlan,
  SweepResult,
} from './types';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

/** Below this, an output is unspendable in practice and relays reject it. */
const DUST_LIMIT_SATS = 546n;

/**
 * A single key can be encoded as several addresses. All of the ones a chain
 * supports are swept together so funds are not silently left behind under a
 * script type the operator forgot they used.
 */
export type BitcoinScriptType = UtxoScriptType;

/** Virtual size each input type contributes, in vbytes. */
const INPUT_VSIZE: Record<BitcoinScriptType, number> = {
  p2wpkh: 68,
  'p2sh-p2wpkh': 91,
  p2pkh: 148,
};

/** Virtual size of one output, by the destination's script type. */
const OUTPUT_VSIZE: Record<string, number> = {
  p2pkh: 34,
  p2sh: 32,
  p2wpkh: 31,
  p2wsh: 43,
  p2tr: 43,
};

interface EsploraUtxo {
  txid: string;
  vout: number;
  value: number;
  status?: { confirmed?: boolean };
}

/** A spendable output, tagged with the script type needed to sign it. */
export interface SweepableUtxo {
  txid: string;
  vout: number;
  value: bigint;
  scriptType: BitcoinScriptType;
  address: string;
}

export interface BitcoinSweepOptions extends SweepOptions {
  /** Which Bitcoin-style chain to sweep. Defaults to Bitcoin. */
  chain?: ChainId;
  endpoints?: string[];
  /** Override the fee rate in sat/vB instead of asking an endpoint. */
  feeRate?: number;
  /**
   * Spend unconfirmed outputs too. Off by default: an unconfirmed parent can
   * still be replaced, which would invalidate the sweep.
   */
  includeUnconfirmed?: boolean;
  /** Seed-phrase mode: consecutive unused addresses that end a scan. */
  gapLimit?: number;
  /** Seed-phrase mode: which account to scan. Wallets show account 0. */
  account?: number;
}

/**
 * Anything that can sign an input.
 *
 * Both a standalone keypair and a derived BIP32 node satisfy this, which is
 * what lets one transaction mix inputs from a single imported key with inputs
 * from a whole derived account.
 */
export interface SweepSigner {
  publicKey: Buffer;
  sign(hash: Buffer, lowR?: boolean): Buffer;
}

interface KnownAddress {
  scriptType: BitcoinScriptType;
  signer: SweepSigner;
  /** Derivation path, when the address came from a seed phrase. */
  path?: string;
}

/** Stops a malformed scan from walking forever. */
const MAX_SCAN_INDEX = 500;

/**
 * Consolidates every UTXO a key controls into a single payment.
 *
 * Bitcoin has no token layer, so a sweep is one transaction: all inputs in,
 * one output to the destination, the fee taken out of the total. There is no
 * change output -- the whole balance moves by construction.
 */
export class BitcoinSweeper {
  /** Addresses discovered so far, and how to sign for each. */
  private readonly known = new Map<string, KnownAddress>();

  private readonly config: UtxoNetworkConfig;
  private readonly root?: BIP32Interface;
  private readonly account: number;
  private readonly gapLimit: number;
  private readonly endpoints: string[];
  private readonly http: AxiosInstance;
  private readonly prices: PriceService;
  private readonly minValueUsd: number;
  private readonly includeUnpriced: boolean;
  private readonly includeUnconfirmed: boolean;
  private readonly feeRateOverride?: number;

  private constructor(root: BIP32Interface | undefined, options: BitcoinSweepOptions) {
    this.config = utxoNetwork(options.chain ?? 'bitcoin');
    this.root = root;
    this.account = options.account ?? 0;
    this.gapLimit = options.gapLimit ?? DEFAULT_GAP_LIMIT;
    this.endpoints = options.endpoints ?? this.config.endpoints;
    this.http = axios.create({ timeout: 20000 });
    this.prices = PriceService.getInstance();
    this.minValueUsd = options.minValueUsd ?? MIN_VALUE_THRESHOLD_USD;
    this.includeUnpriced = options.includeUnpriced ?? false;
    this.includeUnconfirmed = options.includeUnconfirmed ?? false;
    this.feeRateOverride = options.feeRate;
  }

  /**
   * One imported key, in all three of the address forms it can take.
   *
   * This covers a key exported from a wallet, but only the single address that
   * key controls -- see `fromMnemonic` for an HD wallet.
   */
  static fromWif(wif: string, options: BitcoinSweepOptions = {}): BitcoinSweeper {
    const sweeper = new BitcoinSweeper(undefined, options);
    const keyPair = ECPair.fromWIF(wif.trim(), sweeper.config.network);
    const pubkey = Buffer.from(keyPair.publicKey);
    const signer: SweepSigner = { publicKey: pubkey, sign: (hash, lowR) => Buffer.from(keyPair.sign(hash, lowR)) };

    for (const scriptType of sweeper.config.scriptTypes) {
      sweeper.known.set(addressForScriptType(pubkey, scriptType, sweeper.config.network), { scriptType, signer });
    }

    return sweeper;
  }

  /**
   * A whole HD account, derived from a seed phrase.
   *
   * Addresses are discovered by scanning, not assumed, so change outputs -- the
   * ones a single exported key misses -- are swept along with everything else.
   */
  static fromMnemonic(mnemonic: string, passphrase = '', options: BitcoinSweepOptions = {}): BitcoinSweeper {
    return new BitcoinSweeper(rootFromSeed(mnemonicToSeed(mnemonic, passphrase)), options);
  }

  /** True when this sweeper discovers addresses by derivation rather than holding one key. */
  get isHd(): boolean {
    return this.root !== undefined;
  }

  /** Addresses known to hold, or have held, funds. Populated by a scan in HD mode. */
  addresses(): Array<{ scriptType: BitcoinScriptType; address: string; path?: string }> {
    return [...this.known.entries()].map(([address, entry]) => ({
      address,
      scriptType: entry.scriptType,
      path: entry.path,
    }));
  }

  async planSweep(destination: string): Promise<SweepPlan> {
    const utxos = await this.collectUtxos();

    // In HD mode the address set is only known after the scan, so the
    // self-send check has to come after it.
    const to = normalizeBitcoinDestination(
      destination,
      this.addresses().map((entry) => entry.address),
      this.config.network
    );

    if (utxos.length === 0) {
      throw new Error(
        this.isHd
          ? `No ${this.includeUnconfirmed ? '' : 'confirmed '}${this.config.displayName} outputs found across ` +
            `account ${this.account} (scanned ${this.scannedLayouts()}, receive and change, gap limit ${this.gapLimit}).`
          : `No ${this.includeUnconfirmed ? '' : 'confirmed '}outputs found for this key across ` +
            this.addresses().map((entry) => entry.address).join(', ')
      );
    }

    const total = utxos.reduce((sum, utxo) => sum + utxo.value, 0n);
    const feeRate = this.feeRateOverride ?? (await this.fetchFeeRate());
    const vsize = estimateVsize(utxos.map((utxo) => utxo.scriptType), outputTypeOf(to, this.config.network));
    const { amount, fee } = computeSweepAmount(total, vsize, feeRate, this.config.dustLimit);

    const priceUsd = await this.nativePrice();
    const amountBtc = scaleUnits(amount, 8);
    const valueUsd = priceUsd === null ? null : amountBtc * priceUsd;

    const asset: SweepCandidate = {
      symbol: this.config.nativeSymbol,
      name: this.config.nativeName,
      decimals: 8,
      rawAmount: total,
      amount: scaleUnits(total, 8),
      priceUsd,
      valueUsd: priceUsd === null ? null : scaleUnits(total, 8) * priceUsd,
      isNative: true,
    };

    if (valueUsd !== null && valueUsd < this.minValueUsd) {
      throw new Error(
        `After a ${fee} sat fee the sweep would move $${valueUsd.toFixed(2)}, below the $${this.minValueUsd} threshold.`
      );
    }
    if (valueUsd === null && !this.includeUnpriced) {
      throw new Error('Could not resolve a BTC price; re-run with --include-unpriced to sweep anyway.');
    }

    const warnings: string[] = [
      `Fee rate ${feeRate} sat/vB over an estimated ${vsize} vB = ${fee} sats.`,
    ];

    const spread = new Set(utxos.map((utxo) => utxo.address));
    if (spread.size > 1) {
      warnings.push(
        this.isHd
          ? `Funds found across ${spread.size} derived addresses; all are being swept into one transaction.`
          : `This key holds funds under ${spread.size} script types; all are being swept into one transaction.`
      );
    }
    if (this.isHd) {
      warnings.push(
        `Only account ${this.account} was scanned. If this wallet uses further accounts, their funds are not included.`
      );
    }
    if (this.config.chain === 'litecoin') {
      warnings.push('Litecoin and Bitcoin addresses look similar. Confirm the destination is a Litecoin address.');
    }
    if (!this.includeUnconfirmed) {
      warnings.push('Unconfirmed outputs are excluded. Re-run with --include-unconfirmed to spend them too.');
    }

    return {
      chain: this.config.chain,
      source: [...spread].join(', '),
      destination: to,
      nativeSymbol: this.config.nativeSymbol,
      transfers: [{ asset, rawAmount: amount, amount: amountBtc, valueUsd }],
      skipped: [],
      feeReserveRaw: fee,
      feeReserve: scaleUnits(fee, 8),
      transactionCount: 1,
      totalValueUsd: valueUsd ?? 0,
      warnings,
    };
  }

  async executeSweep(plan: SweepPlan): Promise<SweepResult> {
    try {
      const utxos = await this.collectUtxos();
      if (utxos.length === 0) {
        throw new Error('No spendable outputs remain; the plan is stale.');
      }

      const transfer = plan.transfers[0];

      // The plan's amount was computed against a specific input set. If the
      // wallet received or spent anything since, that amount no longer matches
      // the inputs being signed, so rebuild rather than broadcast a bad fee.
      const total = utxos.reduce((sum, utxo) => sum + utxo.value, 0n);
      if (total !== transfer.asset.rawAmount) {
        throw new Error(
          `Balance changed since the plan was made (${transfer.asset.rawAmount} -> ${total} sats). Re-run to rebuild it.`
        );
      }

      const prevTxs = await this.fetchParentTransactions(utxos);
      const psbt = buildSweepPsbt(
        utxos,
        plan.destination,
        transfer.rawAmount,
        prevTxs,
        (address) => this.signerFor(address).publicKey,
        this.config.network
      );

      // Inputs can come from different derived keys, so each is signed with
      // the one that controls its address rather than a single wallet key.
      utxos.forEach((utxo, index) => {
        psbt.signInput(index, this.signerFor(utxo.address));
      });
      psbt.finalizeAllInputs();

      const hex = psbt.extractTransaction().toHex();
      const txid = await this.broadcast(hex);

      const executed: ExecutedTransfer = {
        symbol: this.config.nativeSymbol,
        amount: transfer.amount,
        valueUsd: transfer.valueUsd,
        txHash: txid,
        explorerUrl: `${this.config.explorerTxUrl}/${txid}`,
      };

      return {
        success: true,
        chain: this.config.chain,
        executed: [executed],
        failed: [],
        totalValueUsd: transfer.valueUsd ?? 0,
      };
    } catch (error) {
      return {
        success: false,
        chain: this.config.chain,
        executed: [],
        failed: [
          { symbol: this.config.nativeSymbol, error: error instanceof Error ? error.message : 'Unknown error' },
        ],
        totalValueUsd: 0,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Fetch the parent transaction of every legacy input.
   *
   * A segwit input can be signed from the output it spends alone; a P2PKH
   * input needs the whole parent, so only those are fetched.
   */
  private async fetchParentTransactions(utxos: SweepableUtxo[]): Promise<Map<string, Buffer>> {
    const parents = new Map<string, Buffer>();

    for (const utxo of utxos) {
      if (utxo.scriptType !== 'p2pkh' || parents.has(utxo.txid)) continue;
      parents.set(utxo.txid, await this.fetchRawTransaction(utxo.txid));
    }

    return parents;
  }

  private signerFor(address: string): SweepSigner {
    const entry = this.known.get(address);
    if (!entry) {
      throw new Error(`No key available for ${address}; refusing to sign.`);
    }
    return entry.signer;
  }

  /** Gather spendable outputs from every address this wallet controls. */
  private async collectUtxos(): Promise<SweepableUtxo[]> {
    if (this.root) {
      return this.scanHdAccount(this.root);
    }

    const collected: SweepableUtxo[] = [];
    for (const { scriptType, address } of this.addresses()) {
      collected.push(...(await this.utxosAt(address, scriptType)));
    }
    return collected;
  }

  /**
   * Walk every standard chain of the account, stopping each one after
   * `gapLimit` consecutive unused addresses.
   *
   * Emptiness is judged by transaction history rather than current balance: an
   * address that was used and spent still means later indices may hold funds,
   * and treating it as unused would end the scan early and strand them.
   */
  private async scanHdAccount(root: BIP32Interface): Promise<SweepableUtxo[]> {
    const collected: SweepableUtxo[] = [];

    for (const { purpose, scriptType } of UTXO_PURPOSES) {
      if (!this.config.scriptTypes.includes(scriptType)) continue;

      for (const change of [0, 1] as const) {
        let unusedRun = 0;

        for (let index = 0; unusedRun < this.gapLimit && index < MAX_SCAN_INDEX; index++) {
          const derived = deriveBitcoinKey(root, purpose, this.account, change, index, this.config);

          if ((await this.fetchTransactionCount(derived.address)) === 0) {
            unusedRun++;
            continue;
          }

          unusedRun = 0;
          this.known.set(derived.address, {
            scriptType: derived.scriptType,
            path: derived.path,
            signer: {
              publicKey: Buffer.from(derived.node.publicKey),
              sign: (hash, lowR) => Buffer.from(derived.node.sign(hash, lowR)),
            },
          });

          collected.push(...(await this.utxosAt(derived.address, derived.scriptType)));
        }
      }
    }

    return collected;
  }

  private async utxosAt(address: string, scriptType: BitcoinScriptType): Promise<SweepableUtxo[]> {
    const utxos = await this.fetchUtxos(address);
    const spendable: SweepableUtxo[] = [];

    for (const utxo of utxos) {
      if (!this.includeUnconfirmed && !utxo.status?.confirmed) continue;
      spendable.push({ txid: utxo.txid, vout: utxo.vout, value: BigInt(utxo.value), scriptType, address });
    }

    return spendable;
  }

  /** Total transactions an address has ever appeared in, confirmed or pending. */
  private async fetchTransactionCount(address: string): Promise<number> {
    return this.tryEndpoints(async (endpoint) => {
      const response = await this.http.get<{
        chain_stats?: { tx_count?: number };
        mempool_stats?: { tx_count?: number };
      }>(`${endpoint}/address/${address}`);
      return (response.data?.chain_stats?.tx_count ?? 0) + (response.data?.mempool_stats?.tx_count ?? 0);
    }, `Could not read history for ${address}`);
  }

  /** Which derivation layouts this chain's scan covers, for messages. */
  private scannedLayouts(): string {
    return UTXO_PURPOSES.filter((entry) => this.config.scriptTypes.includes(entry.scriptType))
      .map((entry) => `BIP${entry.purpose}`)
      .join(', ');
  }

  private async nativePrice(): Promise<number | null> {
    const [priced] = await this.prices.priceAssets([
      {
        chain: this.config.chain,
        symbol: this.config.nativeSymbol,
        name: this.config.nativeName,
        amount: 1,
        rawAmount: '100000000',
        decimals: 8,
        priceUsd: null,
        valueUsd: null,
        isNative: true,
      },
    ]);
    return priced.priceUsd;
  }

  private async fetchUtxos(address: string): Promise<EsploraUtxo[]> {
    return this.tryEndpoints(async (endpoint) => {
      const response = await this.http.get<EsploraUtxo[]>(`${endpoint}/address/${address}/utxo`);
      return Array.isArray(response.data) ? response.data : [];
    }, `Could not list outputs for ${address}`);
  }

  private async fetchRawTransaction(txid: string): Promise<Buffer> {
    return this.tryEndpoints(async (endpoint) => {
      const response = await this.http.get<string>(`${endpoint}/tx/${txid}/hex`);
      return Buffer.from(response.data.trim(), 'hex');
    }, `Could not fetch parent transaction ${txid}`);
  }

  /** Ask for a next-block-ish fee rate, in sat/vB. */
  private async fetchFeeRate(): Promise<number> {
    for (const endpoint of this.endpoints) {
      try {
        const recommended = await this.http.get<{ halfHourFee?: number }>(`${endpoint}/v1/fees/recommended`);
        const rate = recommended.data?.halfHourFee;
        if (typeof rate === 'number' && rate > 0) return Math.ceil(rate);
      } catch {
        // Endpoint may not implement mempool.space's extension; try the standard one.
      }

      try {
        const estimates = await this.http.get<Record<string, number>>(`${endpoint}/fee-estimates`);
        const rate = estimates.data?.['3'] ?? estimates.data?.['6'];
        if (typeof rate === 'number' && rate > 0) return Math.ceil(rate);
      } catch {
        // Fall through to the next endpoint.
      }
    }
    return this.config.fallbackFeeRate;
  }

  private async broadcast(hex: string): Promise<string> {
    return this.tryEndpoints(async (endpoint) => {
      const response = await this.http.post<string>(`${endpoint}/tx`, hex, {
        headers: { 'Content-Type': 'text/plain' },
      });
      const txid = String(response.data).trim();
      if (!/^[0-9a-f]{64}$/i.test(txid)) {
        throw new Error(`Unexpected broadcast response: ${txid}`);
      }
      return txid;
    }, 'Could not broadcast the transaction');
  }

  private async tryEndpoints<T>(attempt: (endpoint: string) => Promise<T>, failureMessage: string): Promise<T> {
    let lastError: unknown;
    for (const endpoint of this.endpoints) {
      try {
        return await attempt(endpoint);
      } catch (error) {
        lastError = error;
      }
    }
    throw new Error(`${failureMessage}: ${lastError instanceof Error ? lastError.message : 'all endpoints failed'}`);
  }
}

/**
 * Check a destination is a spendable mainnet address the source key does not
 * already control.
 */
export function normalizeBitcoinDestination(
  destination: string,
  ownAddresses: string[],
  network: bitcoin.Network = bitcoin.networks.bitcoin
): string {
  const value = destination.trim();

  // toOutputScript checks the address against this chain's own version bytes,
  // so a Bitcoin address is rejected on Litecoin and vice versa.
  try {
    bitcoin.address.toOutputScript(value, network);
  } catch {
    throw new Error(`Not a valid mainnet address for this chain: ${destination}`);
  }

  if (ownAddresses.includes(value)) {
    throw new Error('Destination is an address this key already controls; nothing to do.');
  }
  return value;
}

/**
 * Assemble the unsigned sweep: every UTXO in, one output to the destination.
 *
 * Kept free of network and key access so the transaction it produces can be
 * built and inspected in a test with nothing but a keypair.
 */
export function buildSweepPsbt(
  utxos: SweepableUtxo[],
  destination: string,
  amount: bigint,
  parentTransactions: Map<string, Buffer>,
  pubkeyFor: (address: string) => Buffer,
  network: bitcoin.Network = bitcoin.networks.bitcoin
): bitcoin.Psbt {
  const psbt = new bitcoin.Psbt({ network });

  for (const utxo of utxos) {
    const base = { hash: utxo.txid, index: utxo.vout };

    if (utxo.scriptType === 'p2pkh') {
      const parent = parentTransactions.get(utxo.txid);
      if (!parent) {
        throw new Error(`Missing parent transaction ${utxo.txid} for a legacy input.`);
      }
      psbt.addInput({ ...base, nonWitnessUtxo: parent });
      continue;
    }

    // Each input's scripts are built from the key that controls its own
    // address, which need not be the same key across inputs.
    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: pubkeyFor(utxo.address), network });

    if (utxo.scriptType === 'p2sh-p2wpkh') {
      const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network });
      psbt.addInput({
        ...base,
        witnessUtxo: { script: p2sh.output!, value: Number(utxo.value) },
        redeemScript: p2wpkh.output!,
      });
      continue;
    }

    psbt.addInput({ ...base, witnessUtxo: { script: p2wpkh.output!, value: Number(utxo.value) } });
  }

  psbt.addOutput({ address: destination, value: Number(amount) });
  return psbt;
}

/**
 * Virtual size of a sweep transaction, in vbytes.
 *
 * Base overhead is 10 vB; the segwit marker and flag add another 0.5 vB
 * whenever at least one input is segwit, which rounds up to 1.
 */
export function estimateVsize(inputTypes: BitcoinScriptType[], outputType: string): number {
  const inputs = inputTypes.reduce((sum, type) => sum + INPUT_VSIZE[type], 0);
  const output = OUTPUT_VSIZE[outputType] ?? OUTPUT_VSIZE.p2pkh;
  const segwitOverhead = inputTypes.some((type) => type !== 'p2pkh') ? 1 : 0;
  return 10 + segwitOverhead + inputs + output;
}

/** Take the fee out of the total; there is no change output in a sweep. */
export function computeSweepAmount(
  totalSats: bigint,
  vsize: number,
  feeRate: number,
  dustLimit: bigint = DUST_LIMIT_SATS
): { amount: bigint; fee: bigint } {
  const fee = BigInt(Math.ceil(vsize * feeRate));

  if (totalSats <= fee) {
    throw new Error(`Balance of ${totalSats} sats does not cover the ${fee} sat fee.`);
  }

  const amount = totalSats - fee;
  if (amount < dustLimit) {
    throw new Error(`Sweeping would leave a ${amount} sat output, below the ${dustLimit} sat dust limit.`);
  }

  return { amount, fee };
}

/**
 * Classify a destination address so its output size can be costed.
 *
 * Decoding the address is used rather than matching its prefix, because the
 * prefixes differ per chain -- Litecoin's wrapped-segwit addresses start with
 * `M`, not `3` -- while the encoded version byte is authoritative.
 */
export function outputTypeOf(address: string, network: bitcoin.Network = bitcoin.networks.bitcoin): string {
  const value = address.trim();

  try {
    const decoded = bitcoin.address.fromBech32(value);
    if (decoded.version === 1 && decoded.data.length === 32) return 'p2tr';
    return decoded.data.length === 32 ? 'p2wsh' : 'p2wpkh';
  } catch {
    // Not bech32; fall through to base58.
  }

  try {
    return bitcoin.address.fromBase58Check(value).version === network.scriptHash ? 'p2sh' : 'p2pkh';
  } catch {
    return 'p2pkh';
  }
}
