/**
 * Utility functions and helpers
 */

export { PackageResolver } from './package-resolver.js';
export { GitIgnoreParser, createGitIgnoreParser } from './gitignore-parser.js';
export {
  isTestFile,
  isGeneratedFile,
  getFileCategory,
  extractPackageName,
  isRelativeOrAbsoluteImport,
  isNodeBuiltin,
  calculateEntropy,
  extractContextSnippet
} from './file-utils.js';
