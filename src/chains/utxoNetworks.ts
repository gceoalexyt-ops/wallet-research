/**
 * Per-chain parameters for the UTXO chains.
 *
 * Bitcoin and Litecoin share a transaction format, a signing scheme and an
 * Esplora-compatible API, so one implementation covers both once the network
 * bytes and derivation coin type are parameterised. Bitcoin Cash does not: it
 * has no segwit and signs with SIGHASH_FORKID, so it lives in its own module
 * rather than pretending to fit here.
 */

import * as bitcoin from 'bitcoinjs-lib';
import { ChainId } from './types';

/** Address forms a key can take on a Bitcoin-style chain. */
export type UtxoScriptType = 'p2wpkh' | 'p2sh-p2wpkh' | 'p2pkh';

export interface UtxoNetworkConfig {
  chain: ChainId;
  displayName: string;
  nativeSymbol: string;
  nativeName: string;
  coingeckoId: string;
  /** BIP44 coin type: 0 for Bitcoin, 2 for Litecoin. */
  coinType: number;
  network: bitcoin.Network;
  /** Script types in scan order, most modern first. */
  scriptTypes: UtxoScriptType[];
  /** Esplora-compatible API roots, tried in order. */
  endpoints: string[];
  explorerTxUrl: string;
  /** Smallest relayable output, in the chain's smallest unit. */
  dustLimit: bigint;
  /** Used when no endpoint will quote a rate, in sat/vB. */
  fallbackFeeRate: number;
}

/**
 * Litecoin's network bytes.
 *
 * `scriptHash` is 0x32, giving wrapped-segwit addresses the modern `M` prefix
 * rather than the `3` that the legacy 0x05 value produced and that is now
 * ambiguous with Bitcoin.
 */
export const LITECOIN_NETWORK: bitcoin.Network = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'ltc',
  bip32: { public: 0x019da462, private: 0x019d9cfe },
  pubKeyHash: 0x30,
  scriptHash: 0x32,
  wif: 0xb0,
};

export const UTXO_NETWORKS: Record<string, UtxoNetworkConfig> = {
  bitcoin: {
    chain: 'bitcoin',
    displayName: 'Bitcoin',
    nativeSymbol: 'BTC',
    nativeName: 'Bitcoin',
    coingeckoId: 'bitcoin',
    coinType: 0,
    network: bitcoin.networks.bitcoin,
    scriptTypes: ['p2wpkh', 'p2sh-p2wpkh', 'p2pkh'],
    endpoints: ['https://mempool.space/api', 'https://blockstream.info/api'],
    explorerTxUrl: 'https://mempool.space/tx',
    dustLimit: 546n,
    fallbackFeeRate: 10,
  },
  litecoin: {
    chain: 'litecoin',
    displayName: 'Litecoin',
    nativeSymbol: 'LTC',
    nativeName: 'Litecoin',
    coingeckoId: 'litecoin',
    coinType: 2,
    network: LITECOIN_NETWORK,
    scriptTypes: ['p2wpkh', 'p2sh-p2wpkh', 'p2pkh'],
    endpoints: ['https://litecoinspace.org/api'],
    explorerTxUrl: 'https://litecoinspace.org/tx',
    dustLimit: 546n,
    // Litecoin blocks are rarely full; a few sat/vB confirms.
    fallbackFeeRate: 5,
  },
};

/** BIP44 purpose numbers, and the script type each implies. */
export const UTXO_PURPOSES: Array<{ purpose: number; scriptType: UtxoScriptType; label: string }> = [
  { purpose: 84, scriptType: 'p2wpkh', label: 'BIP84 native segwit' },
  { purpose: 49, scriptType: 'p2sh-p2wpkh', label: 'BIP49 wrapped segwit' },
  { purpose: 44, scriptType: 'p2pkh', label: 'BIP44 legacy' },
];

export function utxoNetwork(chain: ChainId): UtxoNetworkConfig {
  const config = UTXO_NETWORKS[chain];
  if (!config) {
    throw new Error(`No UTXO network configuration for ${chain}`);
  }
  return config;
}
