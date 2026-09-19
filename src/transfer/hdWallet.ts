/**
 * BIP39 / BIP32 derivation.
 *
 * A single private key controls a single address, which is not how modern
 * wallets hold funds: Exodus, MetaMask and Phantom all derive many addresses
 * from one seed phrase, and on Bitcoin every transaction routinely sends change
 * to a freshly derived one. Sweeping a single exported key from such a wallet
 * moves part of the balance and silently leaves the rest.
 *
 * This module turns one seed phrase into the set of keys a wallet would
 * actually have used, so a sweep can cover all of them.
 */

import { BIP32Factory, BIP32Interface } from 'bip32';
import * as bip39 from 'bip39';
import * as bitcoin from 'bitcoinjs-lib';
import { computeAddress } from 'ethers';
import * as ecc from 'tiny-secp256k1';
import { UTXO_PURPOSES, UtxoNetworkConfig, UtxoScriptType, utxoNetwork } from '../chains/utxoNetworks';

const bip32 = BIP32Factory(ecc);

/**
 * The three Bitcoin account layouts in general use, and the script type each
 * one implies. A wallet may have used any of them, so all three are scanned.
 */
export const BITCOIN_PURPOSES = UTXO_PURPOSES;

/** How many consecutive unused addresses end a scan, per BIP44. */
export const DEFAULT_GAP_LIMIT = 20;

export interface DerivedBitcoinKey {
  address: string;
  scriptType: UtxoScriptType;
  path: string;
  node: BIP32Interface;
}

export interface DerivedEvmKey {
  address: string;
  path: string;
  privateKey: string;
}

/**
 * Normalize and check a seed phrase.
 *
 * Wordlist validation catches the overwhelmingly common failure -- a mistyped
 * or misremembered word -- before anything touches the network.
 */
export function normalizeMnemonic(mnemonic: string): string {
  const normalized = mnemonic.trim().toLowerCase().split(/\s+/).join(' ');

  if (normalized.length === 0) {
    throw new Error('No seed phrase supplied.');
  }

  const words = normalized.split(' ');
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    throw new Error(`A seed phrase is 12, 15, 18, 21 or 24 words; got ${words.length}.`);
  }

  if (!bip39.validateMnemonic(normalized)) {
    throw new Error(
      'Seed phrase failed its checksum. A word is mistyped, out of order, or not in the BIP39 wordlist.'
    );
  }

  return normalized;
}

/**
 * Turn a phrase into a seed.
 *
 * The optional passphrase is BIP39's 25th word. An incorrect one does not
 * error -- it silently derives a different, empty wallet -- so it is only ever
 * taken explicitly from the operator.
 */
export function mnemonicToSeed(mnemonic: string, passphrase = ''): Buffer {
  return bip39.mnemonicToSeedSync(normalizeMnemonic(mnemonic), passphrase);
}

/** Root node for a seed. */
export function rootFromSeed(seed: Buffer): BIP32Interface {
  return bip32.fromSeed(seed, bitcoin.networks.bitcoin);
}

/**
 * Render one address path.
 *
 * The coin type is what separates one chain's accounts from another's under
 * the same seed: Bitcoin is 0, Litecoin 2, Bitcoin Cash 145.
 */
export function utxoPath(purpose: number, coinType: number, account: number, change: 0 | 1, index: number): string {
  return `m/${purpose}'/${coinType}'/${account}'/${change}/${index}`;
}

/**
 * Derive one Bitcoin address, as the script type its purpose implies.
 *
 * The purpose field is not decoration: a BIP84 account's keys are spent as
 * native segwit, and deriving the same key as legacy would produce an address
 * the wallet never used.
 */
export function deriveBitcoinKey(
  root: BIP32Interface,
  purpose: number,
  account: number,
  change: 0 | 1,
  index: number,
  config: UtxoNetworkConfig = utxoNetwork('bitcoin')
): DerivedBitcoinKey {
  const entry = UTXO_PURPOSES.find((candidate) => candidate.purpose === purpose);
  if (!entry) {
    throw new Error(`Unsupported derivation purpose: ${purpose}`);
  }
  if (!config.scriptTypes.includes(entry.scriptType)) {
    throw new Error(`${config.displayName} does not support ${entry.scriptType} (${entry.label}).`);
  }

  const path = utxoPath(purpose, config.coinType, account, change, index);
  const node = root.derivePath(path);
  const address = addressForScriptType(Buffer.from(node.publicKey), entry.scriptType, config.network);

  return { address, scriptType: entry.scriptType, path, node };
}

/** Build the address a pubkey takes under a given script type. */
export function addressForScriptType(
  pubkey: Buffer,
  scriptType: UtxoScriptType,
  network: bitcoin.Network = bitcoin.networks.bitcoin
): string {
  if (scriptType === 'p2pkh') {
    return bitcoin.payments.p2pkh({ pubkey, network }).address!;
  }

  const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network });
  if (scriptType === 'p2wpkh') {
    return p2wpkh.address!;
  }

  return bitcoin.payments.p2sh({ redeem: p2wpkh, network }).address!;
}

/**
 * Derive an EVM account.
 *
 * m/44'/60'/0'/0/index is the layout MetaMask, Exodus and Phantom all use, so
 * index 0 is the account a wallet shows first.
 */
export function deriveEvmKey(root: BIP32Interface, index = 0): DerivedEvmKey {
  const path = `m/44'/60'/0'/0/${index}`;
  const node = root.derivePath(path);

  if (!node.privateKey) {
    throw new Error(`Derivation produced no private key at ${path}`);
  }

  const privateKey = `0x${Buffer.from(node.privateKey).toString('hex')}`;
  return { address: computeAddress(privateKey), path, privateKey };
}

/**
 * Every address a scan would visit for one account, in order.
 *
 * Both the receive chain and the change chain are covered: on Bitcoin, change
 * is where a used wallet keeps most of its outputs, and it is exactly what a
 * single exported key misses.
 */
export function enumerateBitcoinCandidates(
  root: BIP32Interface,
  account: number,
  gapLimit: number = DEFAULT_GAP_LIMIT,
  config: UtxoNetworkConfig = utxoNetwork('bitcoin')
): DerivedBitcoinKey[] {
  const keys: DerivedBitcoinKey[] = [];

  for (const { purpose, scriptType } of UTXO_PURPOSES) {
    if (!config.scriptTypes.includes(scriptType)) continue;

    for (const change of [0, 1] as const) {
      for (let index = 0; index < gapLimit; index++) {
        keys.push(deriveBitcoinKey(root, purpose, account, change, index, config));
      }
    }
  }

  return keys;
}
