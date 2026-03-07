/**
 * Framework Detector — Auto-detect which web frameworks are in use.
 *
 * Combines package.json dependency analysis with per-file AST detection
 * to determine which framework models should be active during taint analysis.
 */

import * as ts from 'typescript';
import type { FrameworkModel } from './framework-model.js';
import { ExpressModel } from './express-model.js';
import { NestJSModel } from './nestjs-model.js';
import { NextJSModel } from './nextjs-model.js';

// ---------------------------------------------------------------------------
// Package name -> model mapping
// ---------------------------------------------------------------------------

interface FrameworkEntry {
  /** npm package names that indicate this framework */
  packages: string[];
  /** Factory to create the model */
  create: () => FrameworkModel;
}

const FRAMEWORK_REGISTRY: FrameworkEntry[] = [
  {
    packages: ['express', '@types/express', 'express-serve-static-core'],
    create: () => new ExpressModel(),
  },
  {
    packages: ['@nestjs/core', '@nestjs/common', '@nestjs/platform-express', '@nestjs/platform-fastify'],
    create: () => new NestJSModel(),
  },
  {
    packages: ['next'],
    create: () => new NextJSModel(),
  },
];

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

export class FrameworkDetector {
  /**
   * Detect which frameworks are used in the project.
   *
   * Strategy:
   * 1. Check package.json dependencies for known framework packages.
   * 2. For each source file, run each model's `detect()` method.
   * 3. Deduplicate and return instantiated models.
   *
   * @param sourceFiles  Map of file paths to parsed SourceFile objects
   * @param packageJson  Parsed package.json content (optional)
   * @returns Array of instantiated FrameworkModel objects for detected frameworks
   */
  detectFrameworks(
    sourceFiles: Map<string, ts.SourceFile>,
    packageJson?: {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    },
  ): FrameworkModel[] {
    const detected = new Set<string>();
    const models: FrameworkModel[] = [];

    // Phase 1: package.json dependencies
    if (packageJson) {
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
      };

      for (const entry of FRAMEWORK_REGISTRY) {
        if (detected.has(entry.create().name)) continue;

        for (const pkg of entry.packages) {
          if (pkg in allDeps) {
            const model = entry.create();
            detected.add(model.name);
            models.push(model);
            break;
          }
        }
      }
    }

    // Phase 2: AST-based detection on source files
    // Create candidate models for frameworks not yet detected
    const candidates: { entry: FrameworkEntry; model: FrameworkModel }[] = [];
    for (const entry of FRAMEWORK_REGISTRY) {
      const model = entry.create();
      if (!detected.has(model.name)) {
        candidates.push({ entry, model });
      }
    }

    if (candidates.length > 0) {
      for (const [, sourceFile] of sourceFiles) {
        if (candidates.length === 0) break;

        for (let i = candidates.length - 1; i >= 0; i--) {
          const { model } = candidates[i];
          try {
            if (model.detect(sourceFile)) {
              detected.add(model.name);
              models.push(model);
              candidates.splice(i, 1);
            }
          } catch {
            // Malformed file — skip detection for this file/model pair
          }
        }
      }
    }

    return models;
  }

  /**
   * Get all available framework model constructors.
   * Useful for testing or manual instantiation.
   */
  static allModels(): FrameworkModel[] {
    return FRAMEWORK_REGISTRY.map(entry => entry.create());
  }
}
