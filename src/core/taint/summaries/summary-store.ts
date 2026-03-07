/**
 * SummaryStore — Global store for function summaries used in cross-file
 * taint analysis. Provides indexed access by canonical ID and file path,
 * plus serialization for incremental caching.
 */

import type {
  FunctionSummary,
  SummaryStoreStats,
} from './summary-types.js';

export class SummaryStore {
  /** Primary index: canonicalId -> FunctionSummary */
  private readonly byId = new Map<string, FunctionSummary>();

  /** Secondary index: filePath -> Set<canonicalId> */
  private readonly byFile = new Map<string, Set<string>>();

  /** Add a single summary, replacing any existing one with the same canonicalId. */
  add(summary: FunctionSummary): void {
    const prev = this.byId.get(summary.canonicalId);

    // If the summary moved files (unlikely but possible after rename), clean
    // the old file index entry.
    if (prev && prev.filePath !== summary.filePath) {
      const oldSet = this.byFile.get(prev.filePath);
      if (oldSet) {
        oldSet.delete(prev.canonicalId);
        if (oldSet.size === 0) this.byFile.delete(prev.filePath);
      }
    }

    this.byId.set(summary.canonicalId, summary);

    let fileSet = this.byFile.get(summary.filePath);
    if (!fileSet) {
      fileSet = new Set<string>();
      this.byFile.set(summary.filePath, fileSet);
    }
    fileSet.add(summary.canonicalId);
  }

  /** Add multiple summaries at once. */
  addAll(summaries: FunctionSummary[]): void {
    for (const s of summaries) {
      this.add(s);
    }
  }

  /** Get a summary by its canonical ID, or null if not found. */
  get(canonicalId: string): FunctionSummary | null {
    return this.byId.get(canonicalId) ?? null;
  }

  /** Get all summaries belonging to a given file. */
  getForFile(filePath: string): FunctionSummary[] {
    const ids = this.byFile.get(filePath);
    if (!ids) return [];
    const result: FunctionSummary[] = [];
    for (const id of ids) {
      const s = this.byId.get(id);
      if (s) result.push(s);
    }
    return result;
  }

  /** Remove every summary associated with a file (for incremental rebuild). */
  removeFile(filePath: string): void {
    const ids = this.byFile.get(filePath);
    if (!ids) return;
    for (const id of ids) {
      this.byId.delete(id);
    }
    this.byFile.delete(filePath);
  }

  /** Check whether a summary exists for the given canonical ID. */
  has(canonicalId: string): boolean {
    return this.byId.has(canonicalId);
  }

  /** Return every canonical ID in the store. */
  getAllIds(): string[] {
    return Array.from(this.byId.keys());
  }

  /** Compute aggregate statistics. */
  getStats(): SummaryStoreStats {
    let completeSummaries = 0;
    let transferEdges = 0;
    let sinkHits = 0;

    for (const s of this.byId.values()) {
      if (s.isComplete) completeSummaries++;
      transferEdges += s.transfers.length;
      sinkHits += s.sinkHits.length;
    }

    return {
      totalSummaries: this.byId.size,
      completeSummaries,
      filesProcessed: this.byFile.size,
      transferEdges,
      sinkHits,
    };
  }

  /**
   * Serialize the entire store to a JSON string suitable for disk caching.
   *
   * Any `ts.Node` references (which are not serializable) are stripped by a
   * replacer that nulls out `node` fields.  All other data is plain JSON.
   */
  serialize(): string {
    const summaries = Array.from(this.byId.values());

    return JSON.stringify(summaries, (_key: string, value: unknown) => {
      // Strip ts.Node references — they contain circular refs and are
      // not meaningful outside the current compiler program.
      if (_key === 'node') return null;
      return value;
    });
  }

  /**
   * Reconstruct a SummaryStore from a JSON string produced by `serialize()`.
   * All loaded summaries are marked `isComplete: true` since they represent
   * previously-computed results.
   */
  static deserialize(json: string): SummaryStore {
    const store = new SummaryStore();
    const summaries: FunctionSummary[] = JSON.parse(json);

    for (const s of summaries) {
      s.isComplete = true;
      store.add(s);
    }

    return store;
  }

  /** Remove all summaries from the store. */
  clear(): void {
    this.byId.clear();
    this.byFile.clear();
  }

  /** Total number of summaries in the store. */
  get size(): number {
    return this.byId.size;
  }
}
