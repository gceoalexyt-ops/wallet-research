import axios, { AxiosInstance } from 'axios';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory, ECPairInterface } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import { scaleUnits } from '../chains/evm';
import { PriceService } from '../pricing/priceService';
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

/** Esplora-compatible endpoints, tried in order -- same defaults as the reader. */
const DEFAULT_ENDPOINTS = ['https://mempool.space/api', 'https://blockstream.info/api'];

/** Below this, an output is unspendable in practice and relays reject it. */
const DUST_LIMIT_SATS = 546n;

/** Used when no endpoint will quote a fee rate. */
const FALLBACK_FEE_RATE = 10;

/**
 * A single key can be encoded as several addresses. All three are swept
 * together so funds are not silently left behind under a script type the
 * operator forgot they used.
 */
export type BitcoinScriptType = 'p2wpkh' | 'p2sh-p2wpkh' | 'p2pkh';

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
  endpoints?: string[];
  /** Override the fee rate in sat/vB instead of asking an endpoint. */
  feeRate?: number;
  /**
   * Spend unconfirmed outputs too. Off by default: an unconfirmed parent can
   * still be replaced, which would invalidate the sweep.
   */
  includeUnconfirmed?: boolean;
}

/**
 * Consolidates every UTXO a key controls into a single payment.
 *
 * Bitcoin has no token layer, so a sweep is one transaction: all inputs in,
 * one output to the destination, the fee taken out of the total. There is no
 * change output -- the whole balance moves by construction.
 */
export class BitcoinSweeper {
  private readonly keyPair: ECPairInterface;
  private readonly endpoints: string[];
  private readonly http: AxiosInstance;
  private readonly prices: PriceService;
  private readonly minValueUsd: number;
  private readonly includeUnpriced: boolean;
  private readonly includeUnconfirmed: boolean;
  private readonly feeRateOverride?: number;

  constructor(wif: string, options: BitcoinSweepOptions = {}) {
    this.keyPair = ECPair.fromWIF(wif.trim(), bitcoin.networks.bitcoin);
    this.endpoints = options.endpoints ?? DEFAULT_ENDPOINTS;
    this.http = axios.create({ timeout: 20000 });
    this.prices = PriceService.getInstance();
    this.minValueUsd = options.minValueUsd ?? MIN_VALUE_THRESHOLD_USD;
    this.includeUnpriced = options.includeUnpriced ?? false;
    this.includeUnconfirmed = options.includeUnconfirmed ?? false;
    this.feeRateOverride = options.feeRate;
  }

  /** Every address this key can spend from, by script type. */
  addresses(): Array<{ scriptType: BitcoinScriptType; address: string }> {
    const pubkey = Buffer.from(this.keyPair.publicKey);
    const network = bitcoin.networks.bitcoin;

    const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network });
    const p2pkh = bitcoin.payments.p2pkh({ pubkey, network });
    const p2sh = bitcoin.payments.p2sh({ redeem: p2wpkh, network });

    return [
      { scriptType: 'p2wpkh', address: p2wpkh.address! },
      { scriptType: 'p2sh-p2wpkh', address: p2sh.address! },
      { scriptType: 'p2pkh', address: p2pkh.address! },
    ];
  }

  async planSweep(destination: string): Promise<SweepPlan> {
    const to = normalizeBitcoinDestination(
      destination,
      this.addresses().map((entry) => entry.address)
    );
    const utxos = await this.collectUtxos();

    if (utxos.length === 0) {
      throw new Error(
        `No ${this.includeUnconfirmed ? '' : 'confirmed '}outputs found for this key across ` +
          this.addresses().map((entry) => entry.address).join(', ')
      );
    }

    const total = utxos.reduce((sum, utxo) => sum + utxo.value, 0n);
    const feeRate = this.feeRateOverride ?? (await this.fetchFeeRate());
    const vsize = estimateVsize(utxos.map((utxo) => utxo.scriptType), outputTypeOf(to));
    const { amount, fee } = computeSweepAmount(total, vsize, feeRate);

    const priceUsd = await this.btcPrice();
    const amountBtc = scaleUnits(amount, 8);
    const valueUsd = priceUsd === null ? null : amountBtc * priceUsd;

    const asset: SweepCandidate = {
      symbol: 'BTC',
      name: 'Bitcoin',
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
      warnings.push(`This key holds funds under ${spread.size} script types; all are being swept into one transaction.`);
    }
    if (!this.includeUnconfirmed) {
      warnings.push('Unconfirmed outputs are excluded. Re-run with --include-unconfirmed to spend them too.');
    }

    return {
      chain: 'bitcoin',
      source: [...spread].join(', '),
      destination: to,
      nativeSymbol: 'BTC',
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
        Buffer.from(this.keyPair.publicKey),
        utxos,
        plan.destination,
        transfer.rawAmount,
        prevTxs
      );

      psbt.signAllInputs(this.keyPair);
      psbt.finalizeAllInputs();

      const hex = psbt.extractTransaction().toHex();
      const txid = await this.broadcast(hex);

      const executed: ExecutedTransfer = {
        symbol: 'BTC',
        amount: transfer.amount,
        valueUsd: transfer.valueUsd,
        txHash: txid,
        explorerUrl: `https://mempool.space/tx/${txid}`,
      };

      return { success: true, chain: 'bitcoin', executed: [executed], failed: [], totalValueUsd: transfer.valueUsd ?? 0 };
    } catch (error) {
      return {
        success: false,
        chain: 'bitcoin',
        executed: [],
        failed: [{ symbol: 'BTC', error: error instanceof Error ? error.message : 'Unknown error' }],
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

  /** Gather spendable outputs across every script type this key controls. */
  private async collectUtxos(): Promise<SweepableUtxo[]> {
    const collected: SweepableUtxo[] = [];

    for (const { scriptType, address } of this.addresses()) {
      const utxos = await this.fetchUtxos(address);
      for (const utxo of utxos) {
        if (!this.includeUnconfirmed && !utxo.status?.confirmed) continue;
        collected.push({
          txid: utxo.txid,
          vout: utxo.vout,
          value: BigInt(utxo.value),
          scriptType,
          address,
        });
      }
    }

    return collected;
  }

  private async btcPrice(): Promise<number | null> {
    const [priced] = await this.prices.priceAssets([
      {
        chain: 'bitcoin',
        symbol: 'BTC',
        name: 'Bitcoin',
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
    return FALLBACK_FEE_RATE;
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
export function normalizeBitcoinDestination(destination: string, ownAddresses: string[]): string {
  const value = destination.trim();

  try {
    bitcoin.address.toOutputScript(value, bitcoin.networks.bitcoin);
  } catch {
    throw new Error(`Not a valid Bitcoin mainnet address: ${destination}`);
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
  pubkey: Buffer,
  utxos: SweepableUtxo[],
  destination: string,
  amount: bigint,
  parentTransactions: Map<string, Buffer>
): bitcoin.Psbt {
  const network = bitcoin.networks.bitcoin;
  const psbt = new bitcoin.Psbt({ network });
  const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network });

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

/** Classify a destination address so its output size can be costed. */
export function outputTypeOf(address: string): string {
  const value = address.trim();
  if (/^bc1p/i.test(value)) return 'p2tr';
  if (/^bc1q/i.test(value)) return value.length > 50 ? 'p2wsh' : 'p2wpkh';
  if (/^3/.test(value)) return 'p2sh';
  return 'p2pkh';
}
