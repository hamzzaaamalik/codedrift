/**
 * Typosquat Detection Utilities
 * Detects packages that are likely typosquats of popular packages
 */

/**
 * List of popular npm packages that are commonly typosquatted
 * Based on npm download stats and known supply chain attacks
 */
export const POPULAR_PACKAGES = [
  // Top downloaded packages
  'react', 'react-dom', 'lodash', 'express', 'axios', 'typescript', 'webpack',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'babel', 'commander',
  'chalk', 'inquirer', 'yargs', 'dotenv', 'bcrypt', 'jsonwebtoken',
  'mongoose', 'sequelize', 'redis', 'socket.io', 'next', 'vue', 'angular',
  'prisma', 'graphql', 'apollo', 'tailwind', 'vite', 'rollup', 'esbuild',

  // Common utility packages
  'moment', 'dayjs', 'date-fns', 'uuid', 'validator', 'async', 'request',
  'bluebird', 'ramda', 'underscore', 'debug', 'colors', 'ora', 'boxen',

  // Security packages
  'helmet', 'cors', 'cookie-parser', 'body-parser', 'express-validator',
  'passport', 'passport-jwt', 'passport-local', 'express-session',

  // Testing packages
  'cypress', 'puppeteer', 'playwright', 'supertest', 'sinon', 'ava',

  // Build tools
  'gulp', 'grunt', 'parcel', 'browserify', 'tsup', 'unbuild',

  // Framework packages
  'nestjs', 'fastify', 'koa', 'hapi', 'nuxt', 'gatsby', 'remix',

  // Database clients
  'mongodb', 'mysql', 'pg', 'sqlite3', 'knex', 'typeorm',
];

/**
 * Calculate Levenshtein distance between two strings
 * (minimum number of single-character edits needed to transform one string into another)
 */
export function levenshteinDistance(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix: number[][] = [];

  // Initialize matrix
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  // Fill matrix
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Check if a package name is a potential typosquat of a popular package
 * Returns { isTyposquat: boolean, targetPackage: string | null, distance: number }
 */
export function checkTyposquat(packageName: string): {
  isTyposquat: boolean;
  targetPackage: string | null;
  distance: number;
  confidence: 'high' | 'medium' | 'low';
} {
  // Skip scoped packages for now (they're less commonly typosquatted)
  if (packageName.startsWith('@')) {
    return { isTyposquat: false, targetPackage: null, distance: 0, confidence: 'low' };
  }

  let closestPackage: string | null = null;
  let minDistance = Infinity;

  for (const popularPkg of POPULAR_PACKAGES) {
    const distance = levenshteinDistance(packageName.toLowerCase(), popularPkg.toLowerCase());

    if (distance < minDistance && distance > 0) {
      minDistance = distance;
      closestPackage = popularPkg;
    }
  }

  // Determine if it's a typosquat based on edit distance
  // High confidence: 1-2 character difference
  // Medium confidence: 3 character difference
  // Low/no match: 4+ characters
  if (minDistance <= 2) {
    return {
      isTyposquat: true,
      targetPackage: closestPackage,
      distance: minDistance,
      confidence: 'high',
    };
  } else if (minDistance === 3) {
    return {
      isTyposquat: true,
      targetPackage: closestPackage,
      distance: minDistance,
      confidence: 'medium',
    };
  }

  return { isTyposquat: false, targetPackage: null, distance: minDistance, confidence: 'low' };
}

/**
 * Check for common typosquat patterns
 * Returns true if the package matches a known attack pattern
 */
export function hasTyposquatPattern(packageName: string, targetPackage: string): boolean {
  const name = packageName.toLowerCase();
  const target = targetPackage.toLowerCase();

  // Common typosquat patterns
  const patterns = [
    // Missing character: expres vs express
    () => name.length === target.length - 1 && target.includes(name),

    // Extra character: expresss vs express
    () => name.length === target.length + 1 && name.includes(target),

    // Swapped adjacent characters: reatc vs react
    () => {
      for (let i = 0; i < target.length - 1; i++) {
        const swapped = target.slice(0, i) + target[i + 1] + target[i] + target.slice(i + 2);
        if (swapped === name) return true;
      }
      return false;
    },

    // Common character substitutions
    () => {
      const substitutions: Record<string, string[]> = {
        '0': ['o'],
        '1': ['l', 'i'],
        '3': ['e'],
        '5': ['s'],
        'o': ['0'],
        'l': ['1', 'i'],
        'i': ['1', 'l'],
        'e': ['3'],
        's': ['5'],
      };

      for (let i = 0; i < target.length; i++) {
        const char = target[i];
        const subs = substitutions[char];
        if (subs) {
          for (const sub of subs) {
            const variant = target.slice(0, i) + sub + target.slice(i + 1);
            if (variant === name) return true;
          }
        }
      }
      return false;
    },
  ];

  return patterns.some(pattern => pattern());
}
