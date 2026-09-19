/**
 * Bitcoin Cash sweeps.
 *
 * BCH does not fit the Bitcoin/Litecoin implementation in `bitcoinSweeper`:
 * it has no segwit, so only the BIP44 legacy layout exists, and every input is
 * signed with SIGHASH_FORKID over a BIP143-style digest that bitcoinjs-lib
 * cannot produce. bitcore-lib-cash handles both, along with CashAddr encoding,
 * so it is used here rather than reimplementing the sighash.
 */

import axios, { AxiosInstance } from 'axios';
import { BIP32Interface } from 'bip32';
import * as bitcoin from 'bitcoinjs-lib';
import { scaleUnits } from '../chains/evm';
import { PriceService } from '../pricing/priceService';
import {
  DEFAULT_GAP_LIMIT,
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

// bitcore-lib-cash ships no type declarations; the surface used here is small
// and wrapped by the narrow interfaces below.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bch = require('bitcore-lib-cash');

/** BIP44 coin type for Bitcoin Cash. */
export const BCH_COIN_TYPE = 145;

/** BCH has no segwit, so every input and output is pay-to-pubkey-hash. */
const P2PKH_INPUT_BYTES = 148;
const P2PKH_OUTPUT_BYTES = 34;
const TX_OVERHEAD_BYTES = 10;

const DUST_LIMIT_SATS = 546n;

/** BCH blocks are rarely full; 1 sat/byte relays, 2 is comfortable. */
const DEFAULT_FEE_RATE = 2;

const DEFAULT_ENDPOINTS = ['https://api.blockchair.com/bitcoin-cash'];
const EXPLORER_TX_URL = 'https://blockchair.com/bitcoin-cash/transaction';

/** Addresses per Blockchair request; the API takes a comma-separated list. */
const SCAN_BATCH_SIZE = 20;
const MAX_SCAN_INDEX = 500;

export interface BchUtxo {
  txid: string;
  vout: number;
  value: bigint;
  address: string;
}

export interface BitcoinCashSweepOptions extends SweepOptions {
  endpoints?: string[];
  /** Fee rate in sat/byte. */
  feeRate?: number;
  gapLimit?: number;
  account?: number;
  /**
   * Accept a legacy `1...` destination. Off by default, because such an
   * address is equally valid on Bitcoin and there is no way to tell which
   * chain the operator meant.
   */
  allowLegacyDestination?: boolean;
}

interface KnownBchAddress {
  privateKey: unknown;
  path?: string;
}

/**
 * Consolidates every UTXO a BCH key controls into a single payment.
 *
 * As on Bitcoin, a sweep is one transaction with no change output: all inputs
 * in, one output to the destination, the fee taken out of the total.
 */
export class BitcoinCashSweeper {
  private readonly known = new Map<string, KnownBchAddress>();

  private readonly root?: BIP32Interface;
  private readonly account: number;
  private readonly gapLimit: number;
  private readonly endpoints: string[];
  private readonly http: AxiosInstance;
  private readonly prices: PriceService;
  private readonly minValueUsd: number;
  private readonly includeUnpriced: boolean;
  private readonly feeRate: number;
  private readonly allowLegacyDestination: boolean;

  private constructor(root: BIP32Interface | undefined, options: BitcoinCashSweepOptions) {
    this.root = root;
    this.account = options.account ?? 0;
    this.gapLimit = options.gapLimit ?? DEFAULT_GAP_LIMIT;
    this.endpoints = options.endpoints ?? DEFAULT_ENDPOINTS;
    this.http = axios.create({ timeout: 20000 });
    this.prices = PriceService.getInstance();
    this.minValueUsd = options.minValueUsd ?? MIN_VALUE_THRESHOLD_USD;
    this.includeUnpriced = options.includeUnpriced ?? false;
    this.feeRate = options.feeRate ?? DEFAULT_FEE_RATE;
    this.allowLegacyDestination = options.allowLegacyDestination ?? false;
  }

  static fromWif(wif: string, options: BitcoinCashSweepOptions = {}): BitcoinCashSweeper {
    const sweeper = new BitcoinCashSweeper(undefined, options);
    // A WIF carries its own compression flag, so it is trusted as written.
    const privateKey = bch.PrivateKey.fromWIF(wif.trim());
    sweeper.known.set(cashAddressOf(privateKey), { privateKey });
    return sweeper;
  }

  static fromMnemonic(
    mnemonic: string,
    passphrase = '',
    options: BitcoinCashSweepOptions = {}
  ): BitcoinCashSweeper {
    return new BitcoinCashSweeper(rootFromSeed(mnemonicToSeed(mnemonic, passphrase)), options);
  }

  get isHd(): boolean {
    return this.root !== undefined;
  }

  addresses(): Array<{ address: string; path?: string }> {
    return [...this.known.entries()].map(([address, entry]) => ({ address, path: entry.path }));
  }

  async planSweep(destination: string): Promise<SweepPlan> {
    const utxos = await this.collectUtxos();
    const to = normalizeBchDestination(
      destination,
      this.addresses().map((entry) => entry.address),
      this.allowLegacyDestination
    );

    if (utxos.length === 0) {
      throw new Error(
        this.isHd
          ? `No Bitcoin Cash outputs found across account ${this.account} ` +
            `(scanned BIP44 receive and change, gap limit ${this.gapLimit}).`
          : `No Bitcoin Cash outputs found for this key at ${this.addresses().map((e) => e.address).join(', ')}`
      );
    }

    const total = utxos.reduce((sum, utxo) => sum + utxo.value, 0n);
    const size = estimateBchSize(utxos.length, 1);
    const { amount, fee } = computeBchSweepAmount(total, size, this.feeRate);

    const priceUsd = await this.nativePrice();
    const amountBch = scaleUnits(amount, 8);
    const valueUsd = priceUsd === null ? null : amountBch * priceUsd;

    const asset: SweepCandidate = {
      symbol: 'BCH',
      name: 'Bitcoin Cash',
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
      throw new Error('Could not resolve a BCH price; re-run with --include-unpriced to sweep anyway.');
    }

    const spread = new Set(utxos.map((utxo) => utxo.address));
    const warnings = [
      `Fee rate ${this.feeRate} sat/byte over an estimated ${size} bytes = ${fee} sats.`,
      'Bitcoin Cash addresses in legacy form are also valid Bitcoin addresses. Confirm the destination is a BCH wallet.',
    ];

    if (spread.size > 1) {
      warnings.push(`Funds found across ${spread.size} addresses; all are being swept into one transaction.`);
    }
    if (this.isHd) {
      warnings.push(
        `Only account ${this.account} was scanned. If this wallet uses further accounts, their funds are not included.`
      );
    }

    return {
      chain: 'bitcoin-cash',
      source: [...spread].join(', '),
      destination: to,
      nativeSymbol: 'BCH',
      transfers: [{ asset, rawAmount: amount, amount: amountBch, valueUsd }],
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
      const total = utxos.reduce((sum, utxo) => sum + utxo.value, 0n);
      if (total !== transfer.asset.rawAmount) {
        throw new Error(
          `Balance changed since the plan was made (${transfer.asset.rawAmount} -> ${total} sats). Re-run to rebuild it.`
        );
      }

      const transaction = this.buildTransaction(utxos, plan.destination, transfer.rawAmount, total);
      const txid = await this.broadcast(transaction.serialize());

      return {
        success: true,
        chain: 'bitcoin-cash',
        executed: [
          {
            symbol: 'BCH',
            amount: transfer.amount,
            valueUsd: transfer.valueUsd,
            txHash: txid,
            explorerUrl: `${EXPLORER_TX_URL}/${txid}`,
          } satisfies ExecutedTransfer,
        ],
        failed: [],
        totalValueUsd: transfer.valueUsd ?? 0,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        chain: 'bitcoin-cash',
        executed: [],
        failed: [{ symbol: 'BCH', error: message }],
        totalValueUsd: 0,
        error: message,
      };
    }
  }

  private buildTransaction(utxos: BchUtxo[], destination: string, amount: bigint, total: bigint): BchTransaction {
    return buildBchTransaction(utxos, destination, amount, total - amount, (address) => {
      const entry = this.known.get(address);
      if (!entry) throw new Error(`No key available for ${address}; refusing to sign.`);
      return entry.privateKey;
    });
  }

  private async collectUtxos(): Promise<BchUtxo[]> {
    if (!this.root) {
      const collected: BchUtxo[] = [];
      for (const { address } of this.addresses()) {
        collected.push(...(await this.fetchUtxos([address])));
      }
      return collected;
    }

    return this.scanHdAccount(this.root);
  }

  /**
   * Walk the receive and change chains of the account.
   *
   * Addresses are queried in batches because Blockchair accepts a list, and a
   * gap-limit scan over two chains is otherwise dozens of round trips.
   */
  private async scanHdAccount(root: BIP32Interface): Promise<BchUtxo[]> {
    const collected: BchUtxo[] = [];

    for (const change of [0, 1] as const) {
      let unusedRun = 0;
      let index = 0;

      while (unusedRun < this.gapLimit && index < MAX_SCAN_INDEX) {
        const batch: Array<{ address: string; path: string }> = [];

        for (let offset = 0; offset < SCAN_BATCH_SIZE; offset++) {
          const { address, path, privateKey } = deriveBchKey(root, this.account, change, index + offset);
          this.known.set(address, { privateKey, path });
          batch.push({ address, path });
        }

        const activity = await this.fetchAddressActivity(batch.map((entry) => entry.address));

        for (const entry of batch) {
          if ((activity.get(entry.address) ?? 0) === 0) {
            unusedRun++;
          } else {
            unusedRun = 0;
          }
        }

        collected.push(
          ...(await this.fetchUtxos(batch.filter((e) => (activity.get(e.address) ?? 0) > 0).map((e) => e.address)))
        );

        index += SCAN_BATCH_SIZE;
      }
    }

    return collected;
  }

  /** Transaction count per address, used to decide where a scan ends. */
  private async fetchAddressActivity(addresses: string[]): Promise<Map<string, number>> {
    const response = await this.dashboard(addresses);
    const counts = new Map<string, number>();

    for (const address of addresses) {
      const entry = response.addresses?.[stripPrefix(address)] ?? response.addresses?.[address];
      counts.set(address, entry?.transaction_count ?? 0);
    }

    return counts;
  }

  private async fetchUtxos(addresses: string[]): Promise<BchUtxo[]> {
    if (addresses.length === 0) return [];

    const response = await this.dashboard(addresses);
    const byStripped = new Map(addresses.map((address) => [stripPrefix(address), address]));

    return (response.utxo ?? []).map((entry) => ({
      txid: entry.transaction_hash,
      vout: entry.index,
      value: BigInt(entry.value),
      address: byStripped.get(stripPrefix(entry.address)) ?? entry.address,
    }));
  }

  private async dashboard(addresses: string[]): Promise<BlockchairDashboard> {
    const list = addresses.map(stripPrefix).join(',');

    return this.tryEndpoints(async (endpoint) => {
      const response = await this.http.get(`${endpoint}/dashboards/addresses/${list}`);
      const data = response.data?.data;
      if (!data) throw new Error('Unexpected response shape');
      return data as BlockchairDashboard;
    }, `Could not read Bitcoin Cash addresses`);
  }

  private async broadcast(hex: string): Promise<string> {
    return this.tryEndpoints(async (endpoint) => {
      const response = await this.http.post(`${endpoint}/push/transaction`, { data: hex });
      const txid = response.data?.data?.transaction_hash;
      if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/i.test(txid)) {
        throw new Error(`Unexpected broadcast response: ${JSON.stringify(response.data?.data ?? response.data)}`);
      }
      return txid;
    }, 'Could not broadcast the transaction');
  }

  private async nativePrice(): Promise<number | null> {
    const [priced] = await this.prices.priceAssets([
      {
        chain: 'bitcoin-cash',
        symbol: 'BCH',
        name: 'Bitcoin Cash',
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

export interface BchTransaction {
  serialize(): string;
  isFullySigned(): boolean;
  verify(): true | string;
  inputs: Array<{ script: { chunks: Array<{ buf?: Buffer }> } }>;
  outputs: Array<{ satoshis: number; script: unknown }>;
}

/**
 * Build and sign a BCH sweep.
 *
 * bitcore applies SIGHASH_ALL | SIGHASH_FORKID for BCH itself; that 0x41
 * sighash byte is what makes the signature valid on BCH and invalid on
 * Bitcoin, and is asserted in the tests. bitcore's own guards against
 * oversized fees and unsigned inputs are deliberately left switched on -- they
 * are the last check before a transaction becomes irreversible.
 */
export function buildBchTransaction(
  utxos: BchUtxo[],
  destination: string,
  amount: bigint,
  fee: bigint,
  keyFor: (address: string) => unknown
): BchTransaction {
  const inputs = utxos.map((utxo) => ({
    txId: utxo.txid,
    outputIndex: utxo.vout,
    address: utxo.address,
    script: bch.Script.buildPublicKeyHashOut(new bch.Address(utxo.address)).toHex(),
    satoshis: Number(utxo.value),
  }));

  const transaction: BchTransaction = new bch.Transaction()
    .from(inputs)
    .to(destination, Number(amount))
    .fee(Number(fee))
    .sign(utxos.map((utxo) => keyFor(utxo.address)));

  if (!transaction.isFullySigned()) {
    throw new Error('Transaction is not fully signed; refusing to broadcast.');
  }

  const verified = transaction.verify();
  if (verified !== true) {
    throw new Error(`bitcore rejected the built transaction: ${verified}`);
  }

  return transaction;
}

/**
 * Derive the CashAddr and signing key for one BCH derivation path.
 *
 * The key is constructed from its hex form, not via `PrivateKey.fromBuffer`:
 * that overload defaults to an *uncompressed* public key, which hashes to a
 * different address than any HD wallet derives. Getting this wrong makes a
 * scan look at addresses the wallet never used and report an empty account.
 */
export function deriveBchKey(root: BIP32Interface, account: number, change: 0 | 1, index: number) {
  const path = `m/44'/${BCH_COIN_TYPE}'/${account}'/${change}/${index}`;
  const node = root.derivePath(path);
  const privateKey = new bch.PrivateKey(Buffer.from(node.privateKey!).toString('hex'), bch.Networks.livenet);

  if (privateKey.compressed !== true) {
    throw new Error('Derived an uncompressed BCH key; refusing to use an address no wallet would derive.');
  }

  return { path, privateKey, address: cashAddressOf(privateKey) as string };
}

interface BlockchairDashboard {
  addresses?: Record<string, { transaction_count?: number; balance?: number }>;
  utxo?: Array<{ address: string; transaction_hash: string; index: number; value: number }>;
}

/** Blockchair keys its responses by the bare address, without the URI scheme. */
export function stripPrefix(address: string): string {
  return address.replace(/^bitcoincash:/i, '');
}

/**
 * CashAddr form of a key.
 *
 * Always CashAddr, never bitcore's `toLegacyAddress()`: that returns a
 * BitPay-format address with version byte 0x1c and a `C` prefix, which is not
 * the standard BCH legacy encoding and which most wallets reject.
 */
function cashAddressOf(privateKey: { toAddress(): { toCashAddress(): string } }): string {
  return privateKey.toAddress().toCashAddress();
}

/** Standard BCH legacy encoding: base58check over the hash160 with version 0x00. */
export function legacyAddressOf(cashAddress: string): string {
  const address = new bch.Address(cashAddress);
  return bitcoin.address.toBase58Check(Buffer.from(address.hashBuffer), 0x00);
}

/**
 * Convert a standard legacy address to CashAddr.
 *
 * bitcore's own Address constructor rejects a `1...` address, because for
 * legacy input it expects BitPay's `C...` format. Decoding the base58 and
 * rebuilding from the hash160 avoids that quirk.
 */
function cashAddressFromLegacy(legacy: string): { toCashAddress(): string } {
  const { version, hash } = bitcoin.address.fromBase58Check(legacy);

  if (version === 0x00) {
    return bch.Address.fromPublicKeyHash(Buffer.from(hash), bch.Networks.livenet);
  }
  if (version === 0x05) {
    return bch.Address.fromScriptHash(Buffer.from(hash), bch.Networks.livenet);
  }

  throw new Error(`Unrecognised legacy address version ${version}`);
}

/**
 * Check a BCH destination.
 *
 * A legacy `1...` address is rejected unless explicitly allowed: the same
 * string is a valid Bitcoin address, so accepting it silently risks sending
 * BCH to an address the operator holds only on Bitcoin.
 */
export function normalizeBchDestination(
  destination: string,
  ownAddresses: string[],
  allowLegacy = false
): string {
  const value = destination.trim();

  if (!allowLegacy && /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(value)) {
    throw new Error(
      `${value} is a legacy-format address, which is equally valid on Bitcoin. ` +
        'Use the CashAddr form (bitcoincash:q...) so the intended chain is unambiguous.'
    );
  }

  let address: { toCashAddress(): string };
  try {
    address = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(value)
      ? cashAddressFromLegacy(value)
      : new bch.Address(value);
  } catch {
    throw new Error(`Not a valid Bitcoin Cash address: ${destination}`);
  }

  const normalized = address.toCashAddress();
  if (ownAddresses.map(stripPrefix).includes(stripPrefix(normalized))) {
    throw new Error('Destination is an address this key already controls; nothing to do.');
  }

  return normalized;
}

/** Size of a P2PKH-only transaction, in bytes. BCH has no witness discount. */
export function estimateBchSize(inputCount: number, outputCount: number): number {
  return TX_OVERHEAD_BYTES + inputCount * P2PKH_INPUT_BYTES + outputCount * P2PKH_OUTPUT_BYTES;
}

/** Take the fee out of the total; a sweep has no change output. */
export function computeBchSweepAmount(
  totalSats: bigint,
  sizeBytes: number,
  feeRate: number,
  dustLimit: bigint = DUST_LIMIT_SATS
): { amount: bigint; fee: bigint } {
  const fee = BigInt(Math.ceil(sizeBytes * feeRate));

  if (totalSats <= fee) {
    throw new Error(`Balance of ${totalSats} sats does not cover the ${fee} sat fee.`);
  }

  const amount = totalSats - fee;
  if (amount < dustLimit) {
    throw new Error(`Sweeping would leave a ${amount} sat output, below the ${dustLimit} sat dust limit.`);
  }

  return { amount, fee };
}
