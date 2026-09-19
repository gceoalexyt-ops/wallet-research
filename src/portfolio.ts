import { BitcoinAdapter } from './chains/bitcoin';
import { BitcoinCashAdapter } from './chains/bitcoinCash';
import { EVM_CHAINS, EvmAdapter } from './chains/evm';
import { SolanaAdapter } from './chains/solana';
import { AddressPortfolio, AssetBalance, ChainAdapter, ChainId, Portfolio } from './chains/types';
import { utxoNetwork } from './chains/utxoNetworks';
import { PriceService } from './pricing/priceService';

export interface AddressQuery {
  chain: ChainId;
  address: string;
}

export interface PortfolioOptions {
  /** Override the default public RPC for a chain, e.g. { ethereum: '<url>' }. */
  rpcUrls?: Partial<Record<ChainId, string>>;
}

/** Build the full set of read-only chain adapters. */
export function createAdapters(options: PortfolioOptions = {}): Map<ChainId, ChainAdapter> {
  const adapters = new Map<ChainId, ChainAdapter>();

  adapters.set('bitcoin', new BitcoinAdapter(undefined, utxoNetwork('bitcoin')));
  adapters.set('litecoin', new BitcoinAdapter(undefined, utxoNetwork('litecoin')));
  adapters.set('bitcoin-cash', new BitcoinCashAdapter());
  adapters.set('solana', new SolanaAdapter(options.rpcUrls?.solana));

  for (const config of EVM_CHAINS) {
    adapters.set(config.chain, new EvmAdapter(config, options.rpcUrls?.[config.chain]));
  }

  return adapters;
}

/**
 * Guess which chains an address could belong to, by format alone.
 *
 * An EVM address is valid on every EVM chain at once, so this returns all of
 * them and lets the caller query each.
 */
const UTXO_PREFIXED = /^(1|3|bc1|L|M|ltc1|bitcoincash:|[qp][023456789acdefghjklmnpqrstuvwxyz]{38,})/;

export function detectChains(address: string, adapters: Map<ChainId, ChainAdapter>): ChainId[] {
  const value = address.trim();
  const matches: ChainId[] = [];

  for (const [chain, adapter] of adapters) {
    if (adapter.isValidAddress(value)) matches.push(chain);
  }

  // Base58 addresses on Solana and the UTXO chains can satisfy each other's
  // format check. A recognised version prefix is the reliable discriminator,
  // so when one is present Solana is dropped rather than guessed at.
  if (matches.includes('solana') && matches.some((chain) => UTXO_PREFIXED.test(value) && chain !== 'solana')) {
    return matches.filter((chain) => chain !== 'solana');
  }

  return matches;
}

/**
 * Read balances for each address and attach USD valuations.
 *
 * A chain that fails is recorded on its own entry; the rest of the portfolio
 * still reports, so one unreachable RPC never blanks the whole view.
 */
export async function inspectPortfolio(queries: AddressQuery[], options: PortfolioOptions = {}): Promise<Portfolio> {
  const adapters = createAdapters(options);
  const priceService = PriceService.getInstance();

  const entries = await Promise.all(
    queries.map(async (query): Promise<AddressPortfolio> => {
      const adapter = adapters.get(query.chain);
      if (!adapter) {
        return { chain: query.chain, address: query.address, assets: [], totalValueUsd: 0, unpricedCount: 0, error: `Unsupported chain: ${query.chain}` };
      }

      try {
        const balances = await adapter.getBalances(query.address);
        return summarize(query.chain, query.address, await priceService.priceAssets(balances));
      } catch (error) {
        return {
          chain: query.chain,
          address: query.address,
          assets: [],
          totalValueUsd: 0,
          unpricedCount: 0,
          error: error instanceof Error ? error.message : 'Unknown error',
        };
      }
    })
  );

  return {
    addresses: entries,
    totalValueUsd: entries.reduce((sum, entry) => sum + entry.totalValueUsd, 0),
    generatedAt: new Date().toISOString(),
  };
}

function summarize(chain: ChainId, address: string, assets: AssetBalance[]): AddressPortfolio {
  const sorted = [...assets].sort((a, b) => (b.valueUsd ?? -1) - (a.valueUsd ?? -1));

  return {
    chain,
    address,
    assets: sorted,
    totalValueUsd: sorted.reduce((sum, asset) => sum + (asset.valueUsd ?? 0), 0),
    unpricedCount: sorted.filter((asset) => asset.valueUsd === null).length,
  };
}
