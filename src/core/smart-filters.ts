/**
 * Smart Filters - Auto-ignore common false positive patterns
 * Reduces noise by identifying patterns developers intentionally use
 */

import type { Issue } from '../types/index.js';

/**
 * Check if an issue should be auto-ignored based on common patterns
 * @param issue - Issue to check
 * @returns true if issue should be ignored
 */
export function shouldAutoIgnore(issue: Issue): boolean {
  // Fire-and-forget patterns that are intentional
  if (isIntentionalFireAndForget(issue)) {
    return true;
  }

  // Development utilities that are expected to use console
  if (isDevelopmentUtility(issue)) {
    return true;
  }

  // Empty catch in specific acceptable scenarios
  if (isAcceptableEmptyCatch(issue)) {
    return true;
  }

  // Low-priority IDOR issues (authenticated routes, internal APIs)
  if (isLowPriorityIDOR(issue)) {
    return true;
  }

  return false;
}

/**
 * Check if IDOR/validation issue is low priority
 * Internal routes, authenticated-only routes are lower risk
 */
function isLowPriorityIDOR(issue: Issue): boolean {
  if (issue.engine !== 'idor' && !issue.message.toLowerCase().includes('validation')) {
    return false;
  }

  const filePath = issue.filePath.toLowerCase();

  // Internal API routes (not public-facing)
  if (filePath.includes('/internal/') || filePath.includes('/admin/')) {
    return true; // Admin routes usually have auth middleware
  }

  // Health checks, metrics endpoints
  if (filePath.includes('/health') || filePath.includes('/metrics') || filePath.includes('/status')) {
    return true;
  }

  // Only auto-ignore low-confidence IDOR (medium is still worth reporting)
  if (issue.confidence === 'low') {
    return true; // Skip low confidence IDOR
  }

  return false;
}

/**
 * Check if missing-await is intentional fire-and-forget
 */
function isIntentionalFireAndForget(issue: Issue): boolean {
  if (issue.engine !== 'missing-await') {
    return false;
  }

  const message = issue.message.toLowerCase();

  // Common fire-and-forget patterns
  const fireAndForgetPatterns = [
    'log', // logEvent(), logger.log()
    'track', // trackAnalytics()
    'send', // sendNotification()
    'publish', // publishEvent()
    'emit', // eventEmitter.emit()
    'queue', // queueJob()
    'schedule', // scheduleTask()
    'cache', // cacheValue()
  ];

  return fireAndForgetPatterns.some(pattern => message.includes(pattern));
}

/**
 * Check if console usage is in development utility
 */
function isDevelopmentUtility(issue: Issue): boolean {
  if (issue.engine !== 'console-in-production') {
    return false;
  }

  const filePath = issue.filePath.toLowerCase();

  // Already handled by context-aware detection, but double-check
  const devPatterns = [
    '/cli.',
    '/bin/',
    '/scripts/',
    '/tools/',
    'logger.ts',
    'log.ts',
    '/dev/',
    '/debug/',
  ];

  return devPatterns.some(pattern => filePath.includes(pattern));
}

/**
 * Check if empty catch is acceptable in specific scenarios
 */
function isAcceptableEmptyCatch(issue: Issue): boolean {
  if (issue.engine !== 'empty-catch') {
    return false;
  }

  const filePath = issue.filePath.toLowerCase();
  const message = issue.message.toLowerCase();

  // Migration files can have empty catch for rollback
  if (filePath.includes('/migration') || filePath.includes('/seed')) {
    return true;
  }

  // Package resolver trying to load optional files
  if (filePath.includes('package-resolver') || filePath.includes('config')) {
    if (message.includes('silently swallows') || message.includes('empty catch')) {
      return true; // Optional file loading is acceptable
    }
  }

  // Initialization/setup code where errors are expected and ignorable
  if (filePath.includes('/init') || filePath.includes('/setup')) {
    return true;
  }

  return false;
}

/**
 * Get suggested confidence boost for high-quality issues
 * Issues that are almost certainly real problems
 */
export function shouldBoostConfidence(issue: Issue): boolean {
  // Hardcoded secrets with high entropy = definitely real
  if (issue.engine === 'secret-detector' && issue.metadata?.entropy && issue.metadata.entropy > 4.5) {
    return true;
  }

  // SQL injection in production code
  if (issue.engine === 'sql-injection-detector' && !issue.metadata?.isTestFile) {
    return true;
  }

  // XSS in production code
  if (issue.engine === 'xss-detector' && !issue.metadata?.isTestFile) {
    return true;
  }

  // Stack trace exposure in API handlers
  if (issue.engine === 'stack-trace-detector') {
    const filePath = issue.filePath.toLowerCase();
    if (filePath.includes('/api/') || filePath.includes('/route') || filePath.includes('/handler')) {
      return true;
    }
  }

  return false;
}
