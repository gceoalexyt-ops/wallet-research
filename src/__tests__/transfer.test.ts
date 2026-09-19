import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as bitcoin from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as ecc from 'tiny-secp256k1';
import {
  BitcoinSweeper,
  SweepableUtxo,
  buildSweepPsbt,
  computeSweepAmount,
  estimateVsize,
  normalizeBitcoinDestination,
  outputTypeOf,
} from '../transfer/bitcoinSweeper';
import { Transaction, Wallet, recoverAddress } from 'ethers';
import { buildNativeTransfer, normalizeEvmDestination, normalizePrivateKey } from '../transfer/evmSweeper';
import { SweepCandidate, SweepPlan, classifyAssets, withBuffer } from '../transfer/types';
import { BitcoinAdapter } from '../chains/bitcoin';
import { createAdapters, detectChains } from '../portfolio';
import { utxoNetwork } from '../chains/utxoNetworks';
import {
  BchUtxo,
  buildBchTransaction,
  computeBchSweepAmount,
  deriveBchKey,
  estimateBchSize,
  legacyAddressOf,
  normalizeBchDestination,
  stripPrefix,
} from '../transfer/bitcoinCashSweeper';
import { looksLikeMnemonic, renderPlan } from '../transfer/sweepCli';
import {
  deriveBitcoinKey,
  deriveEvmKey,
  enumerateBitcoinCandidates,
  mnemonicToSeed,
  normalizeMnemonic,
  rootFromSeed,
} from '../transfer/hdWallet';

const ECPair = ECPairFactory(ecc);

/**
 * Private key 1, the standard test vector. Its compressed pubkey hashes to
 * 751e76e8199196d454941c45d1b3a323f1433bd6, the BIP173 P2WPKH example.
 */
const WIF_KEY_ONE = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';
const KEY_ONE_P2PKH = '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH';
const KEY_ONE_P2WPKH = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';

const DEST_BECH32 = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq';
const EVM_SOURCE = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
const EVM_DEST = '0x388C818CA8B9251b393131C08a736A67ccB19297';

function candidate(overrides: Partial<SweepCandidate> = {}): SweepCandidate {
  return {
    symbol: 'USDC',
    name: 'USD Coin',
    contract: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    decimals: 6,
    rawAmount: 100_000_000n,
    amount: 100,
    priceUsd: 1,
    valueUsd: 100,
    isNative: false,
    ...overrides,
  };
}

test('classifyAssets moves what clears the threshold and states why the rest stays', () => {
  const { worthMoving, skipped } = classifyAssets(
    [
      candidate({ symbol: 'BIG', valueUsd: 100 }),
      candidate({ symbol: 'DUST', valueUsd: 1.25 }),
      candidate({ symbol: 'EXACT', valueUsd: 5 }),
      candidate({ symbol: 'EMPTY', rawAmount: 0n, valueUsd: 0 }),
    ],
    5,
    false
  );

  assert.deepEqual(worthMoving.map((asset) => asset.symbol), ['BIG', 'EXACT']);
  assert.deepEqual(skipped.map((entry) => entry.asset.symbol), ['DUST', 'EMPTY']);
  assert.match(skipped[0].reason, /below the \$5 threshold/);
  assert.match(skipped[1].reason, /zero balance/);
});

test('classifyAssets leaves unpriced assets behind unless asked otherwise', () => {
  const assets = [candidate({ symbol: 'MYSTERY', priceUsd: null, valueUsd: null })];

  const guarded = classifyAssets(assets, 5, false);
  assert.equal(guarded.worthMoving.length, 0);
  assert.match(guarded.skipped[0].reason, /no price source/);

  const permissive = classifyAssets(assets, 5, true);
  assert.deepEqual(permissive.worthMoving.map((asset) => asset.symbol), ['MYSTERY']);
  assert.equal(permissive.skipped.length, 0);
});

test('withBuffer adds headroom without losing integer precision', () => {
  assert.equal(withBuffer(100n, 25), 125n);
  assert.equal(withBuffer(0n, 25), 0n);
  // Far beyond 2^53: a float would round this, BigInt must not.
  assert.equal(withBuffer(10n ** 30n, 50), 15n * 10n ** 29n);
});

test('normalizePrivateKey accepts either prefix form and rejects the rest', () => {
  const bare = 'a'.repeat(64);
  assert.equal(normalizePrivateKey(bare), `0x${bare}`);
  assert.equal(normalizePrivateKey(`0x${bare}`), `0x${bare}`);
  assert.equal(normalizePrivateKey(`  0X${bare}  `), `0x${bare}`);

  assert.throws(() => normalizePrivateKey('a'.repeat(63)), /32-byte hex/);
  assert.throws(() => normalizePrivateKey('a'.repeat(65)), /32-byte hex/);
  assert.throws(() => normalizePrivateKey('z'.repeat(64)), /32-byte hex/);
  assert.throws(() => normalizePrivateKey(''), /32-byte hex/);
});

test('normalizeEvmDestination catches a broken checksum and a self-send', () => {
  assert.equal(normalizeEvmDestination(EVM_DEST.toLowerCase(), EVM_SOURCE), EVM_DEST);
  assert.equal(normalizeEvmDestination(`  ${EVM_DEST}  `, EVM_SOURCE), EVM_DEST);

  // One character case-flipped: valid hex, invalid EIP-55, almost certainly a typo.
  const broken = '0x388c818CA8B9251b393131C08a736A67ccB19297';
  assert.throws(() => normalizeEvmDestination(broken, EVM_SOURCE), /Not a valid EVM address/);

  assert.throws(() => normalizeEvmDestination(EVM_SOURCE, EVM_SOURCE), /source wallet/);
  assert.throws(() => normalizeEvmDestination(EVM_SOURCE.toLowerCase(), EVM_SOURCE), /source wallet/);
  assert.throws(() => normalizeEvmDestination('not-an-address', EVM_SOURCE), /Not a valid EVM address/);
});

test('buildNativeTransfer sends the balance minus the reserve, and refuses when it cannot', () => {
  const gwei = 10n ** 9n;
  const request = buildNativeTransfer(EVM_DEST, 10n ** 18n, 21_000n * gwei, gwei, gwei / 2n);

  assert.equal(request.value, 10n ** 18n - 21_000n * gwei);
  assert.equal(request.gasLimit, 21_000n);
  assert.equal(request.maxFeePerGas, gwei);
  assert.equal(request.maxPriorityFeePerGas, gwei / 2n);
  assert.equal(request.gasPrice, undefined, 'a 1559 transaction must not also carry a legacy gas price');

  // No EIP-1559 data: fall back to a legacy gas price.
  const legacy = buildNativeTransfer(EVM_DEST, 10n ** 18n, 21_000n * gwei, gwei, null);
  assert.equal(legacy.gasPrice, gwei);
  assert.equal(legacy.maxFeePerGas, undefined);

  // A balance that exactly covers the fee leaves nothing to send.
  assert.throws(() => buildNativeTransfer(EVM_DEST, 21_000n * gwei, 21_000n * gwei, gwei, null), /Nothing left to sweep/);
  assert.throws(() => buildNativeTransfer(EVM_DEST, 1n, 21_000n * gwei, gwei, null), /Nothing left to sweep/);
});

test('a native sweep signs into a transaction that recovers to the source wallet', async () => {
  const wallet = new Wallet(normalizePrivateKey('7'.repeat(64)));
  const gwei = 10n ** 9n;
  const request = buildNativeTransfer(EVM_DEST, 10n ** 18n, 21_000n * gwei, gwei, gwei / 2n);

  // chainId is what binds the signature to one network; an unsigned transfer
  // replayed on another chain is the failure mode this guards.
  const signed = await wallet.signTransaction({ ...request, chainId: 8453, nonce: 3 });
  const parsed = Transaction.from(signed);

  assert.equal(parsed.chainId, 8453n);
  assert.equal(parsed.to, EVM_DEST);
  assert.equal(parsed.value, 10n ** 18n - 21_000n * gwei);
  assert.equal(parsed.gasLimit, 21_000n);
  assert.equal(parsed.from, wallet.address);
  assert.equal(recoverAddress(parsed.unsignedHash, parsed.signature!), wallet.address);
});

test('BitcoinSweeper derives every script type a key can spend from', () => {
  const sweeper = BitcoinSweeper.fromWif(WIF_KEY_ONE);
  const derived = sweeper.addresses();

  assert.deepEqual(
    derived.map((entry) => entry.scriptType),
    ['p2wpkh', 'p2sh-p2wpkh', 'p2pkh']
  );

  // Cross-checked against the published vectors for private key 1.
  assert.equal(derived[0].address, KEY_ONE_P2WPKH);
  assert.equal(derived[2].address, KEY_ONE_P2PKH);
  assert.match(derived[1].address, /^3/);
});

test('normalizeBitcoinDestination rejects malformed, testnet and self-directed addresses', () => {
  const own = BitcoinSweeper.fromWif(WIF_KEY_ONE).addresses().map((entry) => entry.address);

  assert.equal(normalizeBitcoinDestination(DEST_BECH32, own), DEST_BECH32);
  assert.equal(normalizeBitcoinDestination(`  ${DEST_BECH32}  `, own), DEST_BECH32);

  assert.throws(() => normalizeBitcoinDestination(KEY_ONE_P2WPKH, own), /already controls/);
  assert.throws(() => normalizeBitcoinDestination(KEY_ONE_P2PKH, own), /already controls/);
  assert.throws(() => normalizeBitcoinDestination('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', own), /not a valid/i);
  assert.throws(() => normalizeBitcoinDestination(EVM_SOURCE, own), /not a valid/i);
});

test('estimateVsize prices each input type and the segwit marker', () => {
  // 10 base + 1 segwit marker + 68 input + 31 output.
  assert.equal(estimateVsize(['p2wpkh'], 'p2wpkh'), 110);
  // Legacy only: no marker byte.
  assert.equal(estimateVsize(['p2pkh'], 'p2pkh'), 192);
  assert.equal(estimateVsize(['p2wpkh', 'p2wpkh'], 'p2wpkh'), 178);
  assert.equal(estimateVsize(['p2sh-p2wpkh'], 'p2wpkh'), 133);
  // A mixed set still pays the marker exactly once.
  assert.equal(estimateVsize(['p2wpkh', 'p2pkh'], 'p2tr'), 10 + 1 + 68 + 148 + 43);
});

test('outputTypeOf classifies each destination family', () => {
  assert.equal(outputTypeOf(DEST_BECH32), 'p2wpkh');
  assert.equal(outputTypeOf('bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297'), 'p2tr');
  assert.equal(outputTypeOf('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'), 'p2sh');
  assert.equal(outputTypeOf('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), 'p2pkh');
});

test('computeSweepAmount takes the fee out of the total and guards the dust limit', () => {
  const { amount, fee } = computeSweepAmount(100_000n, 110, 10);
  assert.equal(fee, 1_100n);
  assert.equal(amount, 98_900n);

  // Fee rounds up, never down, so the transaction cannot underpay.
  assert.equal(computeSweepAmount(100_000n, 110, 10.5).fee, 1_155n);

  assert.throws(() => computeSweepAmount(1_000n, 110, 10), /does not cover the/);
  assert.throws(() => computeSweepAmount(1_100n, 110, 10), /does not cover the/);
  assert.throws(() => computeSweepAmount(1_500n, 110, 10), /dust limit/);
});

test('buildSweepPsbt produces a signable transaction spending every input', () => {
  const keyPair = ECPair.fromWIF(WIF_KEY_ONE, bitcoin.networks.bitcoin);
  const pubkey = Buffer.from(keyPair.publicKey);
  const p2wpkh = bitcoin.payments.p2wpkh({ pubkey, network: bitcoin.networks.bitcoin });

  const utxos: SweepableUtxo[] = [
    { txid: '1'.repeat(64), vout: 0, value: 60_000n, scriptType: 'p2wpkh', address: KEY_ONE_P2WPKH },
    { txid: '2'.repeat(64), vout: 1, value: 40_000n, scriptType: 'p2wpkh', address: KEY_ONE_P2WPKH },
  ];

  const vsize = estimateVsize(utxos.map((utxo) => utxo.scriptType), outputTypeOf(DEST_BECH32));
  const { amount } = computeSweepAmount(100_000n, vsize, 10);

  const psbt = buildSweepPsbt(utxos, DEST_BECH32, amount, new Map(), () => pubkey);
  psbt.signAllInputs(keyPair);

  assert.ok(psbt.validateSignaturesOfAllInputs(validator), 'every input should carry a valid signature');

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();

  assert.equal(tx.ins.length, 2);
  assert.equal(tx.outs.length, 1, 'a sweep has no change output');
  assert.equal(tx.outs[0].value, Number(amount));
  assert.equal(bitcoin.address.fromOutputScript(tx.outs[0].script, bitcoin.networks.bitcoin), DEST_BECH32);

  // The real size must not exceed what the fee was calculated against.
  assert.ok(tx.virtualSize() <= vsize, `actual ${tx.virtualSize()} vB should fit the ${vsize} vB estimate`);
  assert.ok(p2wpkh.output!.equals(bitcoin.payments.p2wpkh({ pubkey }).output!));
});

test('buildSweepPsbt signs a legacy input from its parent transaction', () => {
  const keyPair = ECPair.fromWIF(WIF_KEY_ONE, bitcoin.networks.bitcoin);
  const pubkey = Buffer.from(keyPair.publicKey);
  const p2pkh = bitcoin.payments.p2pkh({ pubkey, network: bitcoin.networks.bitcoin });

  // A synthetic parent paying the legacy address, so the input can be signed
  // offline exactly as it would be against a fetched transaction.
  const parent = new bitcoin.Transaction();
  parent.addInput(Buffer.alloc(32, 9), 0);
  parent.addOutput(p2pkh.output!, 50_000);
  const parentHex = parent.toBuffer();

  const utxos: SweepableUtxo[] = [
    { txid: parent.getId(), vout: 0, value: 50_000n, scriptType: 'p2pkh', address: KEY_ONE_P2PKH },
  ];

  const vsize = estimateVsize(['p2pkh'], outputTypeOf(DEST_BECH32));
  const { amount } = computeSweepAmount(50_000n, vsize, 5);

  const psbt = buildSweepPsbt(utxos, DEST_BECH32, amount, new Map([[parent.getId(), parentHex]]), () => pubkey);
  psbt.signAllInputs(keyPair);
  assert.ok(psbt.validateSignaturesOfAllInputs(validator));

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  assert.equal(tx.ins.length, 1);
  assert.equal(tx.outs[0].value, Number(amount));
  assert.ok(tx.virtualSize() <= vsize);
});

test('buildSweepPsbt refuses a legacy input with no parent transaction', () => {
  const keyPair = ECPair.fromWIF(WIF_KEY_ONE, bitcoin.networks.bitcoin);
  const utxos: SweepableUtxo[] = [
    { txid: '3'.repeat(64), vout: 0, value: 50_000n, scriptType: 'p2pkh', address: KEY_ONE_P2PKH },
  ];

  assert.throws(
    () => buildSweepPsbt(utxos, DEST_BECH32, 40_000n, new Map(), () => Buffer.from(keyPair.publicKey)),
    /Missing parent transaction/
  );
});

test('renderPlan shows what moves, what stays and the fee reserve', () => {
  const plan: SweepPlan = {
    chain: 'ethereum',
    source: EVM_SOURCE,
    destination: EVM_DEST,
    nativeSymbol: 'ETH',
    transfers: [
      { asset: candidate({ symbol: 'USDC' }), rawAmount: 100_000_000n, amount: 100, valueUsd: 100 },
      {
        asset: candidate({ symbol: 'ETH', isNative: true, contract: undefined, decimals: 18 }),
        rawAmount: 10n ** 18n,
        amount: 1,
        valueUsd: 3000,
      },
    ],
    skipped: [{ asset: candidate({ symbol: 'DUST' }), reason: 'worth $1.00, below the $5 threshold' }],
    feeReserveRaw: 10n ** 15n,
    feeReserve: 0.001,
    transactionCount: 2,
    totalValueUsd: 3100,
    warnings: ['This sweep broadcasts 2 separate transactions.'],
  };

  const output = renderPlan(plan);

  assert.match(output, /USDC/);
  assert.match(output, /ETH/);
  assert.match(output, new RegExp(EVM_DEST));
  assert.match(output, /Leaving behind:/);
  assert.match(output, /DUST\s+worth \$1\.00/);
  assert.match(output, /Fee reserve: 0\.00100000 ETH/);
  assert.match(output, /\$3,100\.00 across 2 transaction\(s\)/);
  assert.match(output, /! This sweep broadcasts 2 separate transactions\./);
});

/** bitcoinjs needs an explicit verifier for validateSignaturesOfAllInputs. */
function validator(pubkey: Buffer, msghash: Buffer, signature: Buffer): boolean {
  return ECPair.fromPublicKey(pubkey).verify(msghash, signature);
}

// --- HD wallet derivation -------------------------------------------------

/** The BIP39 all-zero-entropy phrase, used by the BIP49/84 specs themselves. */
const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

test('derivation matches the published BIP84, BIP49 and BIP44 vectors', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));

  // These three are the test vectors in the BIP84 specification itself.
  assert.equal(deriveBitcoinKey(root, 84, 0, 0, 0).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  assert.equal(deriveBitcoinKey(root, 84, 0, 0, 1).address, 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
  assert.equal(deriveBitcoinKey(root, 84, 0, 1, 0).address, 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el');

  assert.equal(deriveBitcoinKey(root, 49, 0, 0, 0).address, '37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf');
  assert.equal(deriveBitcoinKey(root, 44, 0, 0, 0).address, '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA');

  // The address every wallet shows first for this phrase.
  assert.equal(deriveEvmKey(root, 0).address, '0x9858EfFD232B4033E47d90003D41EC34EcaEda94');
  assert.equal(deriveEvmKey(root, 0).path, "m/44'/60'/0'/0/0");
});

test('each purpose derives its own script type, not just its own key', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));

  assert.equal(deriveBitcoinKey(root, 84, 0, 0, 0).scriptType, 'p2wpkh');
  assert.equal(deriveBitcoinKey(root, 49, 0, 0, 0).scriptType, 'p2sh-p2wpkh');
  assert.equal(deriveBitcoinKey(root, 44, 0, 0, 0).scriptType, 'p2pkh');
  assert.throws(() => deriveBitcoinKey(root, 86, 0, 0, 0), /Unsupported derivation purpose/);
});

test('normalizeMnemonic accepts sloppy spacing and rejects a broken checksum', () => {
  assert.equal(normalizeMnemonic(`  ${TEST_MNEMONIC.toUpperCase()}  `), TEST_MNEMONIC);
  assert.equal(normalizeMnemonic(TEST_MNEMONIC.replace(/ /g, '   ')), TEST_MNEMONIC);

  // Valid words, wrong checksum -- the common "one word misremembered" case.
  const wrongChecksum = TEST_MNEMONIC.replace(/about$/, 'abandon');
  assert.throws(() => normalizeMnemonic(wrongChecksum), /checksum/);

  assert.throws(() => normalizeMnemonic('abandon abandon about'), /12, 15, 18, 21 or 24 words/);
  assert.throws(() => normalizeMnemonic(''), /No seed phrase/);
  // A word outside the BIP39 list.
  assert.throws(() => normalizeMnemonic(TEST_MNEMONIC.replace(/^abandon/, 'zzzzzz')), /checksum|wordlist/);
});

test('a BIP39 passphrase derives a completely different wallet', () => {
  const plain = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const guarded = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC, 'correct horse'));

  assert.notEqual(deriveBitcoinKey(guarded, 84, 0, 0, 0).address, deriveBitcoinKey(plain, 84, 0, 0, 0).address);
  assert.notEqual(deriveEvmKey(guarded, 0).address, deriveEvmKey(plain, 0).address);
});

test('a scan covers the change chain, which is what a single key misses', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const candidates = enumerateBitcoinCandidates(root, 0, 5);

  // Three purposes x receive and change x five indices.
  assert.equal(candidates.length, 30);
  assert.ok(candidates.some((key) => key.path === "m/84'/0'/0'/1/0"), 'change chain must be scanned');
  assert.ok(candidates.some((key) => key.path === "m/44'/0'/0'/1/4"));
  assert.equal(new Set(candidates.map((key) => key.address)).size, 30, 'every derived address should be distinct');
});

test('looksLikeMnemonic separates a phrase from a key', () => {
  assert.ok(looksLikeMnemonic(TEST_MNEMONIC));
  assert.ok(looksLikeMnemonic('  abandon about  '));
  assert.ok(!looksLikeMnemonic(WIF_KEY_ONE));
  assert.ok(!looksLikeMnemonic(`0x${'a'.repeat(64)}`));
});

test('one transaction can spend inputs held by different derived keys', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));

  // A receive address and a change address: exactly the spread that makes a
  // single exported key insufficient for an HD wallet.
  const receive = deriveBitcoinKey(root, 84, 0, 0, 0);
  const change = deriveBitcoinKey(root, 84, 0, 1, 0);
  assert.notEqual(receive.address, change.address);

  const byAddress = new Map([
    [receive.address, receive.node],
    [change.address, change.node],
  ]);

  const utxos: SweepableUtxo[] = [
    { txid: 'a'.repeat(64), vout: 0, value: 70_000n, scriptType: 'p2wpkh', address: receive.address },
    { txid: 'b'.repeat(64), vout: 1, value: 30_000n, scriptType: 'p2wpkh', address: change.address },
  ];

  const vsize = estimateVsize(['p2wpkh', 'p2wpkh'], outputTypeOf(DEST_BECH32));
  const { amount } = computeSweepAmount(100_000n, vsize, 8);

  const psbt = buildSweepPsbt(utxos, DEST_BECH32, amount, new Map(), (address) =>
    Buffer.from(byAddress.get(address)!.publicKey)
  );

  // Each input is signed by the key that controls its own address.
  utxos.forEach((utxo, index) => psbt.signInput(index, byAddress.get(utxo.address)!));
  assert.ok(psbt.validateSignaturesOfAllInputs(validator), 'both inputs should verify under their own key');

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();

  assert.equal(tx.ins.length, 2);
  assert.equal(tx.outs.length, 1);
  assert.equal(tx.outs[0].value, Number(amount));
  assert.ok(tx.virtualSize() <= vsize);
});

test('signing the wrong input with the wrong derived key fails verification', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const receive = deriveBitcoinKey(root, 84, 0, 0, 0);
  const other = deriveBitcoinKey(root, 84, 0, 0, 1);

  const utxos: SweepableUtxo[] = [
    { txid: 'c'.repeat(64), vout: 0, value: 50_000n, scriptType: 'p2wpkh', address: receive.address },
  ];

  const psbt = buildSweepPsbt(utxos, DEST_BECH32, 45_000n, new Map(), () => Buffer.from(receive.node.publicKey));

  // bitcoinjs refuses a key that does not match the input's script.
  assert.throws(() => psbt.signInput(0, other.node), /Can not sign for this input/i);
});

// --- Litecoin -------------------------------------------------------------

const LTC = utxoNetwork('litecoin');
const BTC = utxoNetwork('bitcoin');

test('Litecoin derives under coin type 2 with its own address prefixes', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));

  const native = deriveBitcoinKey(root, 84, 0, 0, 0, LTC);
  const wrapped = deriveBitcoinKey(root, 49, 0, 0, 0, LTC);
  const legacy = deriveBitcoinKey(root, 44, 0, 0, 0, LTC);

  assert.equal(native.path, "m/84'/2'/0'/0/0");
  assert.match(native.address, /^ltc1q/);
  assert.match(wrapped.address, /^M/, 'modern Litecoin P2SH uses version 0x32, giving an M prefix');
  assert.match(legacy.address, /^L/);

  // The same key encoded under Bitcoin's bytes must carry an identical
  // payload: only the network bytes may differ, never the key handling.
  const asBitcoin = bitcoin.payments.p2wpkh({
    pubkey: Buffer.from(native.node.publicKey),
    network: bitcoin.networks.bitcoin,
  }).address!;
  assert.equal(
    bitcoin.address.fromBech32(native.address).data.toString('hex'),
    bitcoin.address.fromBech32(asBitcoin).data.toString('hex')
  );
  assert.equal(bitcoin.address.fromBech32(native.address).prefix, 'ltc');
});

test('Litecoin and Bitcoin addresses are rejected on each other chain', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const ltcAddress = deriveBitcoinKey(root, 84, 0, 0, 0, LTC).address;

  // Sending to the right-looking address on the wrong chain is unrecoverable,
  // so each chain must refuse the other's addresses outright.
  assert.throws(() => normalizeBitcoinDestination(DEST_BECH32, [], LTC.network), /not a valid mainnet address/i);
  assert.throws(() => normalizeBitcoinDestination(ltcAddress, [], BTC.network), /not a valid mainnet address/i);
  assert.equal(normalizeBitcoinDestination(ltcAddress, [], LTC.network), ltcAddress);
  assert.throws(() => normalizeBitcoinDestination(ltcAddress, [ltcAddress], LTC.network), /already controls/);
});

test('outputTypeOf reads the version byte, not the prefix', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const wrapped = deriveBitcoinKey(root, 49, 0, 0, 0, LTC).address;

  // Prefix matching would call this p2pkh and underpay the fee.
  assert.equal(outputTypeOf(wrapped, LTC.network), 'p2sh');
  assert.equal(outputTypeOf(deriveBitcoinKey(root, 44, 0, 0, 0, LTC).address, LTC.network), 'p2pkh');
  assert.equal(outputTypeOf(deriveBitcoinKey(root, 84, 0, 0, 0, LTC).address, LTC.network), 'p2wpkh');
});

test('a Litecoin sweep signs offline exactly as a Bitcoin one does', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const key = deriveBitcoinKey(root, 84, 0, 0, 0, LTC);

  const utxos: SweepableUtxo[] = [
    { txid: 'd'.repeat(64), vout: 0, value: 500_000n, scriptType: 'p2wpkh', address: key.address },
  ];
  const destination = deriveBitcoinKey(root, 84, 0, 0, 1, LTC).address;

  const vsize = estimateVsize(['p2wpkh'], outputTypeOf(destination, LTC.network));
  const { amount } = computeSweepAmount(500_000n, vsize, LTC.fallbackFeeRate);

  const psbt = buildSweepPsbt(
    utxos,
    destination,
    amount,
    new Map(),
    () => Buffer.from(key.node.publicKey),
    LTC.network
  );
  psbt.signInput(0, key.node);
  assert.ok(psbt.validateSignaturesOfAllInputs(validator));

  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  assert.equal(tx.outs.length, 1);
  assert.equal(bitcoin.address.fromOutputScript(tx.outs[0].script, LTC.network), destination);
  assert.ok(tx.virtualSize() <= vsize);
});

test('the Litecoin adapter accepts only Litecoin addresses', () => {
  const ltc = new BitcoinAdapter(undefined, LTC);
  const btc = new BitcoinAdapter(undefined, BTC);
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const ltcAddress = deriveBitcoinKey(root, 84, 0, 0, 0, LTC).address;

  assert.ok(ltc.isValidAddress(ltcAddress));
  assert.ok(ltc.isValidAddress(deriveBitcoinKey(root, 44, 0, 0, 0, LTC).address));
  assert.ok(ltc.isValidAddress(deriveBitcoinKey(root, 49, 0, 0, 0, LTC).address));

  assert.ok(!ltc.isValidAddress(DEST_BECH32));
  assert.ok(!ltc.isValidAddress(KEY_ONE_P2PKH));
  assert.ok(!btc.isValidAddress(ltcAddress));
  assert.ok(btc.isValidAddress(DEST_BECH32));
});

// --- Bitcoin Cash ---------------------------------------------------------

test('Bitcoin Cash derives under coin type 145 and agrees with bitcoinjs on the key', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const derived = deriveBchKey(root, 0, 0, 0);

  assert.equal(derived.path, "m/44'/145'/0'/0/0");
  assert.match(derived.address, /^bitcoincash:q/);

  // bitcore and bitcoinjs must agree on the hash160 behind the address.
  const node = root.derivePath("m/44'/145'/0'/0/0");
  const expected = bitcoin.crypto.hash160(Buffer.from(node.publicKey)).toString('hex');
  assert.equal(legacyAddressOf(derived.address), bitcoin.address.toBase58Check(Buffer.from(expected, 'hex'), 0x00));
});

test('legacyAddressOf returns standard BCH legacy, not bitcore BitPay format', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const derived = deriveBchKey(root, 0, 0, 0);

  // bitcore's own toLegacyAddress() emits a BitPay address (version 0x1c, C
  // prefix) that most BCH wallets reject, so it is never surfaced.
  assert.match(legacyAddressOf(derived.address), /^1/);
  assert.match((derived.privateKey as { toAddress(): { toLegacyAddress(): string } }).toAddress().toLegacyAddress(), /^C/);
});

test('normalizeBchDestination demands CashAddr unless legacy is opted into', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const mine = deriveBchKey(root, 0, 0, 0).address;
  const theirs = deriveBchKey(root, 0, 0, 1).address;

  assert.equal(normalizeBchDestination(theirs, [mine]), theirs);
  // A bare prefix-less CashAddr normalizes to the full URI form.
  assert.equal(normalizeBchDestination(stripPrefix(theirs), [mine]), theirs);

  // A legacy address is equally valid on Bitcoin, so it is refused by default.
  const legacy = legacyAddressOf(theirs);
  assert.throws(() => normalizeBchDestination(legacy, [mine]), /equally valid on Bitcoin/);
  assert.equal(normalizeBchDestination(legacy, [mine], true), theirs);

  assert.throws(() => normalizeBchDestination(mine, [mine]), /already controls/);
  assert.throws(() => normalizeBchDestination('not-an-address', [mine]), /Not a valid Bitcoin Cash address/);
});

test('BCH sizing has no witness discount and guards the dust limit', () => {
  // 10 overhead + 148 per input + 34 per output; no segwit anywhere.
  assert.equal(estimateBchSize(1, 1), 192);
  assert.equal(estimateBchSize(3, 1), 488);

  const { amount, fee } = computeBchSweepAmount(100_000n, 192, 2);
  assert.equal(fee, 384n);
  assert.equal(amount, 99_616n);

  assert.throws(() => computeBchSweepAmount(300n, 192, 2), /does not cover the/);
  assert.throws(() => computeBchSweepAmount(900n, 192, 2), /dust limit/);
});

test('a BCH sweep signs with SIGHASH_FORKID and verifies offline', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const first = deriveBchKey(root, 0, 0, 0);
  const second = deriveBchKey(root, 0, 1, 0);
  const destination = deriveBchKey(root, 0, 0, 5).address;

  const utxos: BchUtxo[] = [
    { txid: 'e'.repeat(64), vout: 0, value: 100_000n, address: first.address },
    { txid: 'f'.repeat(64), vout: 1, value: 50_000n, address: second.address },
  ];

  const keys = new Map([
    [first.address, first.privateKey],
    [second.address, second.privateKey],
  ]);

  const { amount, fee } = computeBchSweepAmount(150_000n, estimateBchSize(2, 1), 2);
  const tx = buildBchTransaction(utxos, destination, amount, fee, (address) => keys.get(address));

  assert.equal(tx.verify(), true);
  assert.ok(tx.isFullySigned());
  assert.equal(tx.outputs.length, 1, 'a sweep has no change output');
  assert.equal(tx.outputs[0].satoshis, Number(amount));

  // 0x41 is SIGHASH_ALL | SIGHASH_FORKID: the byte that makes this valid on
  // BCH and invalid on Bitcoin. Plain SIGHASH_ALL (0x01) would be a bug.
  for (const input of tx.inputs) {
    const signature = input.script.chunks[0].buf!;
    assert.equal(signature[signature.length - 1], 0x41);
  }
});

test('buildBchTransaction refuses to sign an input it has no key for', () => {
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const known = deriveBchKey(root, 0, 0, 0);
  const unknown = deriveBchKey(root, 0, 0, 9);

  const utxos: BchUtxo[] = [{ txid: '1'.repeat(64), vout: 0, value: 100_000n, address: unknown.address }];

  assert.throws(
    () => buildBchTransaction(utxos, known.address, 99_000n, 1_000n, () => undefined),
    /not fully signed|No key/i
  );
});

test('address detection keeps the UTXO chains apart', () => {
  const adapters = createAdapters();
  const root = rootFromSeed(mnemonicToSeed(TEST_MNEMONIC));
  const bch = deriveBchKey(root, 0, 0, 0).address;

  assert.deepEqual(detectChains(DEST_BECH32, adapters), ['bitcoin']);
  assert.deepEqual(detectChains(KEY_ONE_P2PKH, adapters), ['bitcoin']);

  for (const purpose of [84, 49, 44]) {
    assert.deepEqual(
      detectChains(deriveBitcoinKey(root, purpose, 0, 0, 0, LTC).address, adapters),
      ['litecoin'],
      `BIP${purpose} Litecoin address should resolve only to Litecoin`
    );
  }

  assert.deepEqual(detectChains(bch, adapters), ['bitcoin-cash']);
  assert.deepEqual(detectChains(stripPrefix(bch), adapters), ['bitcoin-cash']);

  // Solana base58 must not be swallowed by the UTXO format checks.
  assert.deepEqual(detectChains('So11111111111111111111111111111111111111112', adapters), ['solana']);
});
