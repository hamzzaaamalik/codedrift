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

  // React ecosystem
  'react-router', 'react-router-dom', 'react-query', 'react-redux',
  'react-hook-form', 'react-icons', 'react-select', 'react-table',
  'react-dnd', 'react-spring', 'framer-motion', 'styled-components',
  'zustand', 'recoil', 'jotai', 'redux', 'redux-toolkit', 'mobx', 'immer',

  // Node.js HTTP clients
  'node-fetch', 'got', 'cross-fetch', 'ky', 'superagent', 'needle',
  'undici', 'node-axios',

  // Auth and security
  'bcryptjs', 'argon2', 'jose', 'jwks-rsa', 'node-rsa', 'crypto-js',
  'speakeasy', 'node-otp', 'otplib',

  // Cloud SDKs and services
  'aws-sdk', 'firebase', 'firebase-admin', 'stripe', 'twilio', 'sendgrid',
  '@sendgrid/mail', 'nodemailer', 'mailchimp', 'sendbird', 'pusher',
  '@tanstack/react-query',

  // Validation and schema
  'zod', 'yup', 'joi', 'class-validator', 'ajv', 'superstruct', 'io-ts',

  // Database ORMs and query builders
  'drizzle-orm', 'kysely', 'mikro-orm', 'objection',

  // Build and monorepo tools
  'turbo', 'nx', 'lerna', 'changesets', 'wireit', 'rush',

  // Utilities
  'lodash-es', 'nanoid', 'clsx', 'classnames', 'ms', 'p-limit',
  'execa', 'cross-env', 'dotenv-expand', 'env-cmd',
  'glob', 'fast-glob', 'micromatch', 'minimatch',
  'semver', 'node-semver', 'compare-versions',
  'csv-parse', 'papaparse', 'xlsx', 'exceljs',
  'sharp', 'jimp', 'canvas',
  'multer', 'formidable', 'busboy',
  'winston', 'pino', 'bunyan', 'log4js', 'morgan',
  'pm2', 'nodemon', 'concurrently',
  'js-yaml', 'yaml', 'toml', 'ini',
  'compression', 'ioredis', 'kafkajs',
  'cookie-parser', 'body-parser', 'express-session', 'express-validator',
];

/**
 * Known supply chain attack package names mapped to the legitimate package they impersonate.
 * These are hardcoded real-world typosquats — always flagged with high confidence.
 */
export const KNOWN_ATTACK_PACKAGES: Map<string, string> = new Map([
  ['crossenv', 'cross-env'],
  ['cross_env', 'cross-env'],
  ['nodemailer-js', 'nodemailer'],
  ['loadyaml', 'js-yaml'],
  ['babbel', 'babel'],
  ['mongose', 'mongoose'],
  ['expres', 'express'],
  ['expresss', 'express'],
  ['lodas', 'lodash'],
  ['lodash-js', 'lodash'],
  ['recat', 'react'],
  ['reeact', 'react'],
  ['reactt', 'react'],
  ['axois', 'axios'],
  ['axio', 'axios'],
  ['axxios', 'axios'],
  ['webapck', 'webpack'],
  ['webpackk', 'webpack'],
  ['eslint-js', 'eslint'],
  ['typscript', 'typescript'],
  ['typescipt', 'typescript'],
  ['mogoose', 'mongoose'],
  ['chak', 'chalk'],
  ['chalkjs', 'chalk'],
  ['momment', 'moment'],
  ['momnet', 'moment'],
  ['uuidjs', 'uuid'],
  ['socket-io', 'socket.io'],
  ['socketio', 'socket.io'],
  ['nextjs', 'next'],
  ['vuejs', 'vue'],
  ['angularjs', 'angular'],
  ['pasport', 'passport'],
  ['passportjs', 'passport'],
  ['bcrypt-js', 'bcryptjs'],
  ['prismajs', 'prisma'],
  ['graphqll', 'graphql'],
  ['fastifyjs', 'fastify'],
  ['koajs', 'koa'],
  ['nuxtjs', 'nuxt'],
  ['gatbsy', 'gatsby'],
  ['remmix', 'remix'],
  ['node-mailer', 'nodemailer'],
  ['lodashs', 'lodash'],
  ['reactjs', 'react'],
  ['webapack', 'webpack'],
  ['coffescript', 'coffeescript'],
  ['coffe-script', 'coffeescript'],
  ['gruntcli', 'grunt-cli'],
  ['gulp-cli', 'gulp'],
  ['jquerry', 'jquery'],
  ['jquery.js', 'jquery'],
  ['tkinter', 'tk'],
]);

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

  // Check known attack packages first — guaranteed high confidence
  const knownTarget = KNOWN_ATTACK_PACKAGES.get(packageName.toLowerCase());
  if (knownTarget) {
    return { isTyposquat: true, targetPackage: knownTarget, distance: 1, confidence: 'high' };
  }

  // Hyphen/underscore normalization: cross_env vs cross-env
  const normalizedInput = packageName.toLowerCase().replace(/_/g, '-');
  for (const popularPkg of POPULAR_PACKAGES) {
    const normalizedTarget = popularPkg.toLowerCase().replace(/_/g, '-');
    if (normalizedInput === normalizedTarget && packageName.toLowerCase() !== popularPkg.toLowerCase()) {
      return { isTyposquat: true, targetPackage: popularPkg, distance: 1, confidence: 'high' as const };
    }
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
    // Hyphen/underscore confusion: cross_env vs cross-env
    () => name.replace(/_/g, '-') === target || name.replace(/-/g, '_') === target,

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
