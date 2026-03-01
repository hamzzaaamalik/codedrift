/**
 * Hallucinated Dependency Detector
 * Detects imports from packages that don't exist in package.json
 * Priority: HIGHEST (breaks at runtime)
 *
 * Now supports workspace-aware dependency resolution for monorepos
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { getImports, traverse } from '../core/parser.js';
import { isNodeBuiltin, extractPackageName, isRelativeOrAbsoluteImport } from '../utils/file-utils.js';
import * as ts from 'typescript';

export class HallucinatedDepsDetector extends BaseEngine {
  readonly name = 'hallucinated-deps';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    // Get package resolver from context (workspace-aware)
    const packageResolver = context.packageResolver;

    // If no package resolver available, skip analysis
    if (!packageResolver) {
      return issues;
    }

    // Get workspace name for better error messages
    const workspaceName = context.metadata?.workspaceName;

    // Get all static imports from the file
    const imports = getImports(context.sourceFile);

    for (const imp of imports) {
      const packageName = extractPackageName(imp.moduleName);

      // Skip relative/absolute imports
      if (isRelativeOrAbsoluteImport(imp.moduleName)) {
        continue;
      }

      // Skip Node.js built-ins
      if (isNodeBuiltin(packageName)) {
        continue;
      }

      // Check if package exists using workspace-aware resolver
      const exists = packageResolver.packageExistsForFile
        ? packageResolver.packageExistsForFile(packageName, context.filePath)
        : packageResolver.packageExists(packageName);

      if (!exists) {
        // Build workspace-aware error message
        let message = `Hallucinated dependency: '${packageName}' not found in package.json`;
        if (workspaceName) {
          message = `Hallucinated dependency: '${packageName}' not found in workspace '${workspaceName}' package.json`;
        }

        // Report the issue with location from parser
        issues.push({
          engine: this.name,
          severity: 'error',
          message,
          filePath: context.filePath,
          location: imp.location,
          suggestion: `Run 'npm install ${packageName}' or remove import if AI hallucinated this package`,
          confidence: 'high',
          metadata: {
            isTestFile: context.metadata?.isTestFile || false,
            isGeneratedFile: false,
            workspaceName,
            missingPackage: packageName,
          },
        });
      }
    }

    // Also check dynamic imports: import('module')
    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteral(arg)) {
          const moduleName = arg.text;
          const packageName = extractPackageName(moduleName);

          const exists = packageResolver.packageExistsForFile
            ? packageResolver.packageExistsForFile(packageName, context.filePath)
            : packageResolver.packageExists(packageName);

          if (!isRelativeOrAbsoluteImport(moduleName) &&
              !isNodeBuiltin(packageName) &&
              !exists) {

            let message = `Hallucinated dependency in dynamic import: '${packageName}' not found`;
            if (workspaceName) {
              message = `Hallucinated dependency in dynamic import: '${packageName}' not found in workspace '${workspaceName}'`;
            }

            const issue = this.createIssue(context, node, message, {
              severity: 'error',
              confidence: 'high',
              suggestion: `Install ${packageName} or remove dynamic import`,
              metadata: {
                isTestFile: context.metadata?.isTestFile || false,
                isGeneratedFile: false,
                workspaceName,
                missingPackage: packageName,
              },
            });

            if (issue) issues.push(issue);
          }
        }
      }
    });

    return issues;
  }

}
