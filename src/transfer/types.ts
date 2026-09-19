/**
 * Types for the signing layer.
 *
 * This is deliberately a separate layer from `src/chains`: the chain adapters
 * there stay read-only and key-free, and everything that can move funds lives
 * here, behind an explicit plan-then-confirm flow. A sweeper reads balances
 * *through* an adapter but the adapter never learns a key exists.
 */

import { ChainId } from '../chains/types';

/** Default floor, matching the Solana mover: below this, gas costs more than the asset. */
export const MIN_VALUE_THRESHOLD_USD = 5;

/** An asset found in the source wallet, valued and considered for sweeping. */
export interface SweepCandidate {
  symbol: string;
  name: string;
  /** Contract address. Absent for the chain's native asset. */
  contract?: string;
  decimals: number;
  /** Full balance held, in the asset's smallest unit. */
  rawAmount: bigint;
  amount: number;
  priceUsd: number | null;
  valueUsd: number | null;
  isNative: boolean;
}

/** An asset that will be sent, and how much of it. */
export interface PlannedTransfer {
  asset: SweepCandidate;
  /**
   * Amount actually sent, in the smallest unit. Equal to the full balance for
   * tokens; for a native asset it is the balance net of the fee reserve.
   */
  rawAmount: bigint;
  amount: number;
  valueUsd: number | null;
}

/** An asset deliberately left behind, with the reason stated. */
export interface SkippedAsset {
  asset: SweepCandidate;
  reason: string;
}

/**
 * What a sweep would do, computed before anything is signed.
 *
 * Nothing in a plan touches the network beyond reading. It exists so the
 * operator sees the exact set of movements and can decline.
 */
export interface SweepPlan {
  chain: ChainId;
  /** Address derived from the supplied key. */
  source: string;
  destination: string;
  nativeSymbol: string;
  transfers: PlannedTransfer[];
  skipped: SkippedAsset[];
  /** Native units held back to pay for the sweep itself. */
  feeReserveRaw: bigint;
  feeReserve: number;
  /** Number of transactions the sweep will broadcast. */
  transactionCount: number;
  totalValueUsd: number;
  /** Conditions the operator should read before confirming. */
  warnings: string[];
}

export interface ExecutedTransfer {
  symbol: string;
  contract?: string;
  amount: number;
  valueUsd: number | null;
  txHash: string;
  explorerUrl?: string;
}

export interface FailedTransfer {
  symbol: string;
  error: string;
}

export interface SweepResult {
  success: boolean;
  chain: ChainId;
  executed: ExecutedTransfer[];
  failed: FailedTransfer[];
  totalValueUsd: number;
  /** Set when the sweep could not start at all. */
  error?: string;
}

export interface SweepOptions {
  /** Hide and skip assets below this USD value. Defaults to $5. */
  minValueUsd?: number;
  /**
   * Sweep assets no price source could value. Off by default: an unpriced
   * asset may be worth less than the gas spent moving it.
   */
  includeUnpriced?: boolean;
}

/**
 * Split valued assets into what is worth moving and what is not.
 *
 * Pure, so the threshold behaviour is testable without a network or a key.
 */
export function classifyAssets(
  candidates: SweepCandidate[],
  minValueUsd: number,
  includeUnpriced: boolean
): { worthMoving: SweepCandidate[]; skipped: SkippedAsset[] } {
  const worthMoving: SweepCandidate[] = [];
  const skipped: SkippedAsset[] = [];

  for (const asset of candidates) {
    if (asset.rawAmount <= 0n) {
      skipped.push({ asset, reason: 'zero balance' });
      continue;
    }

    if (asset.valueUsd === null) {
      if (includeUnpriced) {
        worthMoving.push(asset);
      } else {
        skipped.push({ asset, reason: 'no price source resolved it; pass --include-unpriced to move it anyway' });
      }
      continue;
    }

    if (asset.valueUsd < minValueUsd) {
      skipped.push({ asset, reason: `worth $${asset.valueUsd.toFixed(2)}, below the $${minValueUsd} threshold` });
      continue;
    }

    worthMoving.push(asset);
  }

  return { worthMoving, skipped };
}

/** Add a percentage of headroom to an integer estimate. */
export function withBuffer(value: bigint, percent: number): bigint {
  return (value * BigInt(100 + Math.round(percent))) / 100n;
}
