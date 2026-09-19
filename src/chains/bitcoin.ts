import axios, { AxiosInstance } from 'axios';
import * as bitcoin from 'bitcoinjs-lib';
import { AssetBalance, ChainAdapter, ChainId } from './types';
import { scaleUnits } from './evm';
import { UtxoNetworkConfig, utxoNetwork } from './utxoNetworks';

interface EsploraStats {
  funded_txo_sum: number;
  spent_txo_sum: number;
}

interface EsploraAddress {
  chain_stats?: EsploraStats;
  mempool_stats?: EsploraStats;
}

/**
 * Watch-only reader for a Bitcoin-style chain, backed by public Esplora
 * instances.
 *
 * Bitcoin and Litecoin share this implementation; only the address prefixes
 * and the API host differ, both of which come from the network config.
 *
 * Balance is derived from funded/spent output sums, with unconfirmed mempool
 * activity folded in so a just-sent transaction is reflected immediately.
 */
export class BitcoinAdapter implements ChainAdapter {
  readonly chain: ChainId;
  readonly displayName: string;
  readonly nativeSymbol: string;

  private readonly config: UtxoNetworkConfig;
  private readonly endpoints: string[];
  private readonly http: AxiosInstance;

  constructor(endpoints?: string[], config: UtxoNetworkConfig = utxoNetwork('bitcoin')) {
    this.config = config;
    this.chain = config.chain;
    this.displayName = config.displayName;
    this.nativeSymbol = config.nativeSymbol;
    this.endpoints = endpoints ?? config.endpoints;
    this.http = axios.create({ timeout: 20000 });
  }

  /**
   * Structural check against this chain's own version bytes.
   *
   * Decoding rather than prefix-matching keeps Bitcoin and Litecoin addresses
   * from being accepted on each other's chain: their base58 versions differ,
   * and their bech32 prefixes are `bc` and `ltc`.
   */
  isValidAddress(address: string): boolean {
    const value = address.trim();

    try {
      const decoded = bitcoin.address.fromBech32(value);
      return decoded.prefix === this.config.network.bech32;
    } catch {
      // Not bech32; fall through to base58.
    }

    try {
      const { version } = bitcoin.address.fromBase58Check(value);
      return version === this.config.network.pubKeyHash || version === this.config.network.scriptHash;
    } catch {
      return false;
    }
  }

  async getBalances(address: string): Promise<AssetBalance[]> {
    const normalized = address.trim();
    if (!this.isValidAddress(normalized)) {
      throw new Error(
        `Not a valid ${this.displayName} address: ${address}. ` +
          'Extended public keys (xpub/ypub/zpub) are not supported yet -- pass individual addresses.'
      );
    }

    const data = await this.fetchAddress(normalized);
    const confirmed = this.netSum(data.chain_stats);
    const unconfirmed = this.netSum(data.mempool_stats);
    const satoshis = confirmed + unconfirmed;

    if (satoshis <= 0n) return [];

    return [
      {
        chain: this.chain,
        symbol: this.config.nativeSymbol,
        name: this.config.nativeName,
        amount: scaleUnits(satoshis, 8),
        rawAmount: satoshis.toString(),
        decimals: 8,
        priceUsd: null,
        valueUsd: null,
        isNative: true,
      },
    ];
  }

  private netSum(stats?: EsploraStats): bigint {
    if (!stats) return 0n;
    return BigInt(stats.funded_txo_sum ?? 0) - BigInt(stats.spent_txo_sum ?? 0);
  }

  private async fetchAddress(address: string): Promise<EsploraAddress> {
    let lastError: unknown;
    for (const endpoint of this.endpoints) {
      try {
        const response = await this.http.get<EsploraAddress>(`${endpoint}/address/${address}`);
        if (response.data && typeof response.data === 'object') return response.data;
      } catch (error) {
        lastError = error;
      }
    }
    throw new Error(
      `Could not reach a ${this.displayName} API for ${address}: ` +
        `${lastError instanceof Error ? lastError.message : 'all endpoints failed'}`
    );
  }
}
