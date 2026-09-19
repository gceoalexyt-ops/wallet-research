import * as readline from 'readline';
import { EVM_CHAINS } from '../chains/evm';
import { ChainId } from '../chains/types';
import { BitcoinCashSweeper } from './bitcoinCashSweeper';
import { BitcoinSweeper } from './bitcoinSweeper';
import { EvmSweeper } from './evmSweeper';
import { deriveEvmKey, mnemonicToSeed, rootFromSeed } from './hdWallet';
import { MIN_VALUE_THRESHOLD_USD, SweepPlan, SweepResult } from './types';

const EVM_CHAIN_IDS = EVM_CHAINS.map((config) => config.chain);
/** Bitcoin-style chains sharing the bitcoinjs implementation. */
const UTXO_CHAIN_IDS: ChainId[] = ['bitcoin', 'litecoin'];

const SWEEPABLE_CHAINS: ChainId[] = [...UTXO_CHAIN_IDS, 'bitcoin-cash', ...EVM_CHAIN_IDS];

interface SweepCliOptions {
  chain?: ChainId;
  destination?: string;
  minValue: number;
  includeUnpriced: boolean;
  includeUnconfirmed: boolean;
  allowLegacyDestination: boolean;
  rpcUrl?: string;
  feeRate?: number;
  account?: number;
  gapLimit?: number;
  help: boolean;
}

export function parseSweepArgs(argv: string[]): SweepCliOptions {
  const options: SweepCliOptions = {
    minValue: MIN_VALUE_THRESHOLD_USD,
    includeUnpriced: false,
    includeUnconfirmed: false,
    allowLegacyDestination: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--chain': {
        const value = (argv[++i] ?? '').toLowerCase() as ChainId;
        if (!SWEEPABLE_CHAINS.includes(value)) {
          throw new Error(`Unsupported chain: ${argv[i]}. Supported: ${SWEEPABLE_CHAINS.join(', ')}`);
        }
        options.chain = value;
        break;
      }
      case '--to':
        options.destination = argv[++i];
        break;
      case '--min-value':
        options.minValue = parseFloat(argv[++i] ?? '') || 0;
        break;
      case '--include-unpriced':
        options.includeUnpriced = true;
        break;
      case '--include-unconfirmed':
        options.includeUnconfirmed = true;
        break;
      case '--allow-legacy-dest':
        options.allowLegacyDestination = true;
        break;
      case '--rpc':
        options.rpcUrl = argv[++i];
        break;
      case '--fee-rate':
        options.feeRate = parseFloat(argv[++i] ?? '') || undefined;
        break;
      case '--account':
        options.account = parseInt(argv[++i] ?? '', 10) || 0;
        break;
      case '--gap-limit':
        options.gapLimit = parseInt(argv[++i] ?? '', 10) || undefined;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
  }

  return options;
}

function usage(): string {
  return [
    'Sweep one wallet you control into another wallet you control.',
    '',
    'Usage:',
    '  npm run sweep -- --chain <chain> --to <address> [options]',
    '',
    'Options:',
    '  --chain <name>           bitcoin, litecoin, bitcoin-cash, ethereum, polygon, arbitrum, optimism, base',
    '  --to <address>           Destination address',
    `  --min-value <usd>        Leave assets below this value behind (default: ${MIN_VALUE_THRESHOLD_USD})`,
    '  --include-unpriced       Also move assets no price source could value',
    '  --include-unconfirmed    Bitcoin/Litecoin only: also spend unconfirmed outputs',
    '  --allow-legacy-dest      Bitcoin Cash only: accept a legacy 1... destination address',
    '  --rpc <url>              EVM only: use a specific RPC endpoint',
    '  --fee-rate <sat/vB>      Bitcoin/Litecoin/BCH only: set the fee rate instead of asking the network',
    '  --account <n>            Seed phrase only: which account to use (default: 0)',
    '  --gap-limit <n>          Seed phrase only: consecutive unused addresses that end a scan (default: 20)',
    '  -h, --help               Show this help',
    '',
    'At the prompt you may enter either a single private key or a BIP39 seed',
    'phrase. A seed phrase is the one that works for HD wallets such as Exodus:',
    'on Bitcoin it scans BIP84, BIP49 and BIP44, receive and change, and sweeps',
    'every funded address into one transaction. A single key covers one address.',
    '',
    'The key or phrase is only ever read from an interactive prompt, never from a',
    'flag or an environment variable, so it does not reach your shell history or',
    'the process list. Nothing is signed until you approve the printed plan.',
    '',
    'For Solana, use `npm start`.',
  ].join('\n');
}

function question(query: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/** Prompt without echoing, so a key is never left on screen. */
function secretQuestion(query: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const iface = rl as unknown as { _writeToOutput: (chunk: string) => void };
  const write = iface._writeToOutput.bind(iface);
  let muted = false;
  iface._writeToOutput = (chunk: string) => {
    if (!muted) write(chunk);
  };

  return new Promise((resolve) => {
    rl.question(query, (answer) => {
      muted = false;
      process.stdout.write('\n');
      rl.close();
      resolve(answer.trim());
    });
    muted = true;
  });
}

function formatAmount(amount: number): string {
  if (amount === 0) return '0';
  if (amount < 0.0001) return amount.toExponential(2);
  if (amount < 1) return amount.toFixed(8);
  if (amount < 1000) return amount.toFixed(6);
  return amount.toLocaleString('en-US', { maximumFractionDigits: 2 });
}

function formatUsd(value: number | null): string {
  if (value === null) return 'unpriced';
  return `$${value.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

/** Render a plan for review. Pure, so the confirmation screen is testable. */
export function renderPlan(plan: SweepPlan): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`Chain:       ${plan.chain}`);
  lines.push(`From:        ${plan.source}`);
  lines.push(`To:          ${plan.destination}`);
  lines.push('');
  lines.push('Will move:');

  if (plan.transfers.length === 0) {
    lines.push('  (nothing)');
  } else {
    for (const transfer of plan.transfers) {
      const label = transfer.asset.symbol.padEnd(8);
      const amount = formatAmount(transfer.amount).padStart(18);
      lines.push(`  ${label} ${amount}   ${formatUsd(transfer.valueUsd).padStart(14)}`);
    }
  }

  if (plan.skipped.length > 0) {
    lines.push('');
    lines.push('Leaving behind:');
    for (const skipped of plan.skipped) {
      lines.push(`  ${skipped.asset.symbol.padEnd(8)} ${skipped.reason}`);
    }
  }

  lines.push('');
  lines.push(`Fee reserve: ${formatAmount(plan.feeReserve)} ${plan.nativeSymbol}`);
  lines.push(`Total value: ${formatUsd(plan.totalValueUsd)} across ${plan.transactionCount} transaction(s)`);

  if (plan.warnings.length > 0) {
    lines.push('');
    for (const warning of plan.warnings) {
      lines.push(`  ! ${warning}`);
    }
  }

  return lines.join('\n');
}

export function renderResult(result: SweepResult): string {
  const lines: string[] = [''];

  for (const item of result.executed) {
    lines.push(`  sent ${formatAmount(item.amount)} ${item.symbol} (${formatUsd(item.valueUsd)})`);
    if (item.explorerUrl) lines.push(`       ${item.explorerUrl}`);
  }

  for (const failure of result.failed) {
    lines.push(`  FAILED ${failure.symbol}: ${failure.error}`);
  }

  lines.push('');
  lines.push(
    result.success
      ? `Done. Moved ${formatUsd(result.totalValueUsd)}.`
      : `Finished with ${result.failed.length} failure(s). Moved ${formatUsd(result.totalValueUsd)}.`
  );

  return lines.join('\n');
}

/** A seed phrase is several words; a key is one token. */
export function looksLikeMnemonic(secret: string): boolean {
  return /\s/.test(secret.trim());
}

async function buildPlan(
  chain: ChainId,
  secret: string,
  passphrase: string,
  destination: string,
  options: SweepCliOptions
): Promise<{ plan: SweepPlan; execute: (plan: SweepPlan) => Promise<SweepResult> }> {
  const fromSeed = looksLikeMnemonic(secret);

  if (chain === 'bitcoin-cash') {
    const bchOptions = {
      minValueUsd: options.minValue,
      includeUnpriced: options.includeUnpriced,
      feeRate: options.feeRate,
      account: options.account,
      gapLimit: options.gapLimit,
      allowLegacyDestination: options.allowLegacyDestination,
    };

    const sweeper = fromSeed
      ? BitcoinCashSweeper.fromMnemonic(secret, passphrase, bchOptions)
      : BitcoinCashSweeper.fromWif(secret, bchOptions);

    if (fromSeed) {
      console.log(`Scanning Bitcoin Cash account ${options.account ?? 0} (BIP44, receive and change)...`);
    }

    return { plan: await sweeper.planSweep(destination), execute: (plan) => sweeper.executeSweep(plan) };
  }

  if (UTXO_CHAIN_IDS.includes(chain)) {
    const bitcoinOptions = {
      chain,
      minValueUsd: options.minValue,
      includeUnpriced: options.includeUnpriced,
      includeUnconfirmed: options.includeUnconfirmed,
      feeRate: options.feeRate,
      account: options.account,
      gapLimit: options.gapLimit,
    };

    const sweeper = fromSeed
      ? BitcoinSweeper.fromMnemonic(secret, passphrase, bitcoinOptions)
      : BitcoinSweeper.fromWif(secret, bitcoinOptions);

    if (fromSeed) {
      console.log(
        `Scanning ${chain} account ${options.account ?? 0} across BIP84, BIP49 and BIP44, receive and change...`
      );
    }

    return { plan: await sweeper.planSweep(destination), execute: (plan) => sweeper.executeSweep(plan) };
  }

  const config = EVM_CHAINS.find((entry) => entry.chain === chain);
  if (!config) throw new Error(`No EVM configuration for ${chain}`);

  let privateKey = secret;
  if (fromSeed) {
    const derived = deriveEvmKey(rootFromSeed(mnemonicToSeed(secret, passphrase)), options.account ?? 0);
    privateKey = derived.privateKey;
    console.log(`Derived ${derived.address} at ${derived.path}.`);
  }

  const sweeper = new EvmSweeper(privateKey, config, {
    rpcUrl: options.rpcUrl,
    minValueUsd: options.minValue,
    includeUnpriced: options.includeUnpriced,
  });
  return { plan: await sweeper.planSweep(destination), execute: (plan) => sweeper.executeSweep(plan) };
}

async function main(): Promise<void> {
  let options: SweepCliOptions;
  try {
    options = parseSweepArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    console.error('\n' + usage());
    process.exitCode = 1;
    return;
  }

  if (options.help) {
    console.log(usage());
    return;
  }

  console.log('Wallet sweep');
  console.log('Moves assets out of a wallet you hold the key for. Use it on your own wallets only.\n');

  let chain = options.chain;
  if (!chain) {
    const answer = (await question(`Chain (${SWEEPABLE_CHAINS.join(' / ')}): `)).toLowerCase() as ChainId;
    if (!SWEEPABLE_CHAINS.includes(answer)) {
      console.error(`Unsupported chain: ${answer}`);
      process.exitCode = 1;
      return;
    }
    chain = answer;
  }

  const destination = options.destination ?? (await question('Destination address: '));
  if (!destination) {
    console.error('A destination address is required.');
    process.exitCode = 1;
    return;
  }

  const secret = await secretQuestion(
    UTXO_CHAIN_IDS.includes(chain) || chain === 'bitcoin-cash'
      ? 'WIF private key or seed phrase (input hidden): '
      : 'Private key or seed phrase (input hidden): '
  );
  if (!secret) {
    console.error('A private key or seed phrase is required.');
    process.exitCode = 1;
    return;
  }

  // BIP39's optional 25th word. A wrong one does not error, it derives a
  // different and empty wallet, so it is asked for rather than assumed.
  let passphrase = '';
  if (looksLikeMnemonic(secret)) {
    passphrase = await secretQuestion('BIP39 passphrase, blank if none (input hidden): ');
  }

  let plan: SweepPlan;
  let execute: (plan: SweepPlan) => Promise<SweepResult>;
  try {
    console.log('\nReading balances and estimating fees...');
    ({ plan, execute } = await buildPlan(chain, secret, passphrase, destination, options));
  } catch (error) {
    console.error(`\nCould not build a plan: ${error instanceof Error ? error.message : error}`);
    process.exitCode = 1;
    return;
  }

  if (plan.transfers.length === 0) {
    console.log(renderPlan(plan));
    console.log('\nNothing is worth moving. No transaction was created.');
    return;
  }

  console.log(renderPlan(plan));

  // Typing the destination back is deliberate: a mistyped address is the one
  // mistake here that cannot be undone.
  const confirmation = await question(`\nType the destination address to confirm, or anything else to cancel:\n> `);
  if (confirmation !== plan.destination) {
    console.log('Cancelled. Nothing was signed.');
    return;
  }

  console.log('\nBroadcasting...');
  const result = await execute(plan);
  console.log(renderResult(result));

  if (!result.success) process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    console.error('Unexpected error:', error);
    process.exitCode = 1;
  });
}
