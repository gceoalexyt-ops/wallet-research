import axios, { AxiosInstance } from 'axios';
import { AssetBalance, ChainAdapter, ChainId } from './types';
import { scaleUnits } from './evm';

/**
 * Watch-only Bitcoin Cash reader.
 *
 * BCH has no Esplora instance to share with Bitcoin and Litecoin, so balances
 * come from Blockchair instead. As everywhere in `src/chains`, this reads
 * public addresses and holds no key material.
 */

const DEFAULT_ENDPOINTS = ['https://api.blockchair.com/bitcoin-cash'];

/** CashAddr body: `q` or `p` followed by the bech32 alphabet, optionally prefixed. */
const CASHADDR = /^(bitcoincash:)?[qp][023456789acdefghjklmnpqrstuvwxyz]{38,}$/;

/** Legacy base58, identical in form to a Bitcoin P2PKH or P2SH address. */
const LEGACY = /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/;

export class BitcoinCashAdapter implements ChainAdapter {
  readonly chain: ChainId = 'bitcoin-cash';
  readonly displayName = 'Bitcoin Cash';
  readonly nativeSymbol = 'BCH';

  private readonly endpoints: string[];
  private readonly http: AxiosInstance;

  constructor(endpoints: string[] = DEFAULT_ENDPOINTS) {
    this.endpoints = endpoints;
    this.http = axios.create({ timeout: 20000 });
  }

  /**
   * Only CashAddr is recognised.
   *
   * A legacy `1...` address is equally valid on Bitcoin, so treating it as BCH
   * on sight would silently route a Bitcoin address to the wrong chain. Pass
   * `bitcoin-cash:1...` explicitly if that is really what you mean.
   */
  isValidAddress(address: string): boolean {
    return CASHADDR.test(address.trim().toLowerCase());
  }

  /** Legacy form, accepted only when the caller named the chain explicitly. */
  isExplicitlyAddressable(address: string): boolean {
    return this.isValidAddress(address) || LEGACY.test(address.trim());
  }

  async getBalances(address: string): Promise<AssetBalance[]> {
    const normalized = address.trim();
    if (!this.isExplicitlyAddressable(normalized)) {
      throw new Error(`Not a valid Bitcoin Cash address: ${address}`);
    }

    const satoshis = await this.fetchBalance(normalized.replace(/^bitcoincash:/i, ''));
    if (satoshis <= 0n) return [];

    return [
      {
        chain: this.chain,
        symbol: 'BCH',
        name: 'Bitcoin Cash',
        amount: scaleUnits(satoshis, 8),
        rawAmount: satoshis.toString(),
        decimals: 8,
        priceUsd: null,
        valueUsd: null,
        isNative: true,
      },
    ];
  }

  private async fetchBalance(address: string): Promise<bigint> {
    let lastError: unknown;

    for (const endpoint of this.endpoints) {
      try {
        const response = await this.http.get(`${endpoint}/dashboards/address/${address}`);
        const balance = response.data?.data?.[address]?.address?.balance;
        if (typeof balance === 'number') return BigInt(balance);
        if (balance === null) return 0n;
      } catch (error) {
        lastError = error;
      }
    }

    throw new Error(
      `Could not reach a Bitcoin Cash API for ${address}: ` +
        `${lastError instanceof Error ? lastError.message : 'all endpoints failed'}`
    );
  }
}
