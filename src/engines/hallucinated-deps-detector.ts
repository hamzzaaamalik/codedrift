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
import { checkTyposquat, hasTyposquatPattern } from '../utils/typosquat-detector.js';
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

      // Debug: Log the first 5 failures to help diagnose workspace issues
      if (!exists && process.env.CODEDRIFT_DEBUG) {
        console.log(`[Hallucinated] Package not found: "${packageName}"`);
        console.log(`[Hallucinated] File: ${context.filePath}`);
        console.log(`[Hallucinated] Workspace: ${workspaceName || 'none'}`);
        console.log('---');
      }

      if (!exists) {
        // Check if this might be a typosquat of a popular package
        const typosquatCheck = checkTyposquat(packageName);

        let message: string;
        let suggestion: string;
        let confidence: 'high' | 'medium' | 'low' = 'high';

        if (typosquatCheck.isTyposquat && typosquatCheck.targetPackage) {
          // Typosquat detected - could be a supply chain attack!
          const hasPattern = hasTyposquatPattern(packageName, typosquatCheck.targetPackage);
          message = `⚠️ SUPPLY CHAIN RISK: '${packageName}' not found. Did you mean '${typosquatCheck.targetPackage}'? (edit distance: ${typosquatCheck.distance})`;

          if (hasPattern) {
            suggestion = `🚨 CRITICAL: This looks like a typosquat attack! Replace '${packageName}' with '${typosquatCheck.targetPackage}'. Common typosquats are used for supply chain attacks.`;
          } else {
            suggestion = `Replace '${packageName}' with '${typosquatCheck.targetPackage}' or install the correct package. Verify this isn't a malicious typosquat.`;
          }

          confidence = typosquatCheck.confidence;
        } else {
          // Standard hallucinated dependency
          message = `Hallucinated dependency: '${packageName}' not found in package.json`;
          if (workspaceName) {
            message = `Hallucinated dependency: '${packageName}' not found in workspace '${workspaceName}' package.json`;
          }
          suggestion = `Run 'npm install ${packageName}' or remove import if AI hallucinated this package`;
        }

        // Report the issue with location from parser
        issues.push({
          engine: this.name,
          severity: 'error',
          message,
          filePath: context.filePath,
          location: imp.location,
          suggestion,
          confidence,
          metadata: {
            isTestFile: context.metadata?.isTestFile || false,
            isGeneratedFile: false,
            workspaceName,
            missingPackage: packageName,
            typosquatTarget: typosquatCheck.targetPackage || undefined,
            typosquatDistance: typosquatCheck.isTyposquat ? typosquatCheck.distance : undefined,
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

            // Check for typosquat
            const typosquatCheck = checkTyposquat(packageName);

            let message: string;
            let suggestion: string;
            let confidence: 'high' | 'medium' | 'low' = 'high';

            if (typosquatCheck.isTyposquat && typosquatCheck.targetPackage) {
              const hasPattern = hasTyposquatPattern(packageName, typosquatCheck.targetPackage);
              message = `⚠️ SUPPLY CHAIN RISK in dynamic import: '${packageName}' not found. Did you mean '${typosquatCheck.targetPackage}'?`;

              if (hasPattern) {
                suggestion = `🚨 CRITICAL: Typosquat attack detected! Replace '${packageName}' with '${typosquatCheck.targetPackage}'`;
              } else {
                suggestion = `Replace '${packageName}' with '${typosquatCheck.targetPackage}' or install the correct package`;
              }

              confidence = typosquatCheck.confidence;
            } else {
              message = `Hallucinated dependency in dynamic import: '${packageName}' not found`;
              if (workspaceName) {
                message = `Hallucinated dependency in dynamic import: '${packageName}' not found in workspace '${workspaceName}'`;
              }
              suggestion = `Install ${packageName} or remove dynamic import`;
            }

            const issue = this.createIssue(context, node, message, {
              severity: 'error',
              confidence,
              suggestion,
              metadata: {
                isTestFile: context.metadata?.isTestFile || false,
                isGeneratedFile: false,
                workspaceName,
                missingPackage: packageName,
                typosquatTarget: typosquatCheck.targetPackage || undefined,
                typosquatDistance: typosquatCheck.isTyposquat ? typosquatCheck.distance : undefined,
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
