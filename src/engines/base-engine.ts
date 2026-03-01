/**
 * Base Analysis Engine
 * All engines should extend this for consistent behavior
 */

import { AnalysisEngine, AnalysisContext, Issue, Severity, Confidence, IssueMetadata } from '../types/index.js';
import { getLocation } from '../core/parser.js';
import { isTestFile, isGeneratedFile } from '../utils/file-utils.js';
import * as ts from 'typescript';

export abstract class BaseEngine implements AnalysisEngine {
  abstract readonly name: string;
  protected readonly defaultSeverity: Severity = 'error';

  /**
   * Main analysis method - must be implemented by subclasses
   */
  abstract analyze(context: AnalysisContext): Promise<Issue[]>;

  /**
   * Helper to create an issue with consistent formatting
   * Returns null if issue is suppressed by comment
   *
   * @param context - Analysis context containing file info
   * @param node - AST node where issue was found
   * @param message - Human-readable issue description
   * @param options - Optional severity, suggestion, confidence, and metadata
   * @returns Issue object or null if suppressed
   */
  protected createIssue(
    context: AnalysisContext,
    node: ts.Node,
    message: string,
    options?: {
      severity?: Severity;
      suggestion?: string;
      confidence?: Confidence;
      metadata?: IssueMetadata;
    }
  ): Issue | null {
    const location = getLocation(node, context.sourceFile);

    // Check for suppression comments
    if (this.isSuppressed(context, location.line)) {
      return null;
    }

    // Build metadata including file categorization
    const isTest = isTestFile(context.filePath);
    const isGenerated = isGeneratedFile(context.filePath);

    const metadata: IssueMetadata = {
      isTestFile: isTest,
      isGeneratedFile: isGenerated,
      workspaceName: context.metadata?.workspaceName,
      ...(options?.metadata || {}),
    };

    // Extract source context snippet (3 lines before + issue line + 3 lines after)
    if (!metadata.contextSnippet) {
      const lines = context.content.split('\n');
      const issueLine = location.line - 1; // convert 1-indexed to 0-indexed
      const startLine = Math.max(0, issueLine - 3);
      const endLine = Math.min(lines.length - 1, issueLine + 3);
      metadata.contextSnippet = lines.slice(startLine, endLine + 1).join('\n');
    }

    // Determine confidence level with automatic downgrade for test/generated files
    let confidence = options?.confidence ?? 'high';

    // Automatic confidence downgrade for test/generated files
    if (isTest || isGenerated) {
      confidence = this.downgradeConfidence(confidence);
    }

    return {
      engine: this.name,
      severity: options?.severity ?? this.defaultSeverity,
      message,
      filePath: context.filePath,
      location,
      suggestion: options?.suggestion,
      confidence,
      metadata,
    };
  }

  /**
   * Downgrade confidence level by one step
   * Used for automatic downgrade in test/generated files
   */
  private downgradeConfidence(confidence: Confidence): Confidence {
    switch (confidence) {
      case 'high':
        return 'medium';
      case 'medium':
        return 'low';
      case 'low':
        return 'low'; // Already at lowest
      default:
        return 'low';
    }
  }

  /**
   * Check if issue is suppressed by comment
   */
  private isSuppressed(context: AnalysisContext, line: number): boolean {
    const content = context.content;
    const lines = content.split('\n');

    // Check line before issue (0-indexed, so line-2)
    const prevLine = lines[line - 2];
    if (prevLine) {
      // codedrift-disable-next-line or codedrift-ignore-next-line
      if (/codedrift-(disable|ignore)-next-line/.test(prevLine)) {
        return true;
      }
    }

    // Check same line (line-1 for 0-indexing)
    const currentLine = lines[line - 1];
    if (currentLine) {
      // codedrift-disable-line (inline comment)
      if (/codedrift-(disable|ignore)-line/.test(currentLine)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if file should be analyzed (can be overridden)
   */
  protected shouldAnalyze(context: AnalysisContext): boolean {
    // Skip test files by default (can be configured later)
    const isTestFile = /\.(test|spec)\.(ts|js|tsx|jsx)$/.test(context.filePath);

    // Can be extended to check config, file patterns, etc.
    return !isTestFile;
  }

  /**
   * Get human-readable severity label
   */
  protected getSeverityLabel(severity: Severity): string {
    const labels: Record<Severity, string> = {
      error: 'CRITICAL',
      warning: 'HIGH',
      info: 'MEDIUM',
    };
    return labels[severity];
  }
}
