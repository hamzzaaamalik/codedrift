/**
 * Utility functions and helpers
 */

export { PackageResolver, extractPackageName } from './package-resolver.js';
export { GitIgnoreParser, createGitIgnoreParser } from './gitignore-parser.js';
export {
  isTestFile,
  isGeneratedFile,
  getFileCategory,
  extractPackageName as extractPackageNameFromModule,
  isRelativeOrAbsoluteImport,
  isNodeBuiltin,
  calculateEntropy,
  extractContextSnippet
} from './file-utils.js';
