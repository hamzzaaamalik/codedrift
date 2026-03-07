/**
 * Validation Checking — sub-module of MissingInputValidationDetector
 *
 * Detects whether a handler uses validation libraries (Joi, Zod, Yup, etc.)
 * and tracks manual per-field validation coverage.
 */

import * as ts from 'typescript';
import { traverse } from '../../core/parser.js';

// ──────────────────── Validation Import Detection ────────────────────

/**
 * Detect which validation libraries are imported in this file.
 */
export function detectValidationImports(sourceFile: ts.SourceFile): Set<string> {
  const imports = new Set<string>();
  traverse(sourceFile, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const mod = node.moduleSpecifier.text.toLowerCase();
      if (mod.includes('superstruct')) imports.add('superstruct');
      if (mod.includes('io-ts') || mod === 'fp-ts/Either') imports.add('io-ts');
      if (mod.includes('valibot')) imports.add('valibot');
      if (mod.includes('@sinclair/typebox')) imports.add('typebox');
      if (mod.includes('class-transformer')) imports.add('class-transformer');
      if (mod.includes('class-validator')) imports.add('class-validator');
      if (mod.includes('zod')) imports.add('zod');
      if (mod.includes('joi') || mod.includes('celebrate')) imports.add('joi');
      if (mod.includes('yup')) imports.add('yup');
      if (mod.includes('ajv')) imports.add('ajv');
      if (mod.includes('runtypes')) imports.add('runtypes');
      if (mod.includes('arktype')) imports.add('arktype');
      if (mod.includes('@vinejs/vine') || mod.includes('vine')) imports.add('vine');
      if (mod.includes('effect/Schema') || mod.includes('@effect/schema')) imports.add('effect-schema');
    }
  });
  return imports;
}

// ──────────────────── Handler Validation Detection ────────────────────

/**
 * Check if handler has validation library calls.
 */
export function hasValidationInHandler(
  node: ts.Node,
  validationImports: Set<string>,
  hasValidationPipe: boolean = false,
): boolean {
  let hasValidation = false;

  traverse(node, (n) => {
    if (hasValidation) return;

    if (ts.isCallExpression(n)) {
      const text = n.getText();

      const validationPatterns: RegExp[] = [
        // Joi
        /joi\.(object|validate|assert)/i,
        /Joi\.validate\(/,
        /\.validate\(/,
        /\.validateAsync\(/,

        // Zod
        /z\.(object|string|number|array|boolean|enum|union)/,
        /\.parse\(/,
        /\.safeParse\(/,
        /\.parseAsync\(/,

        // Yup
        /yup\.(object|string|number|boolean|array)/i,
        /\.validateSync\(/,
        /\.isValid\(/,

        // class-validator
        /\bvalidate\(/,
        /\bvalidateSync\(/,

        // express-validator
        /body\(['"].*['"]\)\..*\(/,
        /param\(['"].*['"]\)\..*\(/,
        /query\(['"].*['"]\)\..*\(/,
        /validationResult\(/,

        // AJV
        /ajv\.validate\(/,
        /ajv\.compile\(/,

        // class-transformer
        /plainToClass\(/,
        /plainToInstance\(/,

        // TypeBox
        /TypeCompiler\.Compile\(/,
        /\.Check\(/,
      ];

      // Import-dependent patterns
      if (validationImports.has('superstruct')) {
        validationPatterns.push(/\bcreate\(/);
        validationPatterns.push(/\bassert\(/);
        validationPatterns.push(/\bis\(/);
      }
      if (validationImports.has('io-ts')) {
        validationPatterns.push(/\.decode\(/);
        validationPatterns.push(/\.is\(/);
        validationPatterns.push(/isLeft\(/);
        validationPatterns.push(/isRight\(/);
      }
      if (validationImports.has('valibot')) {
        validationPatterns.push(/v\.parse\(/);
        validationPatterns.push(/v\.safeParse\(/);
        validationPatterns.push(/v\.is\(/);
      }
      if (validationImports.has('runtypes')) {
        validationPatterns.push(/\.check\(/);
        validationPatterns.push(/\.guard\(/);
      }
      if (validationImports.has('typebox')) {
        validationPatterns.push(/Value\.Check\(/);
        validationPatterns.push(/Value\.Decode\(/);
      }
      if (validationImports.has('arktype')) {
        validationPatterns.push(/\btype\(/);
        validationPatterns.push(/\bscope\(/);
      }
      if (validationImports.has('vine')) {
        validationPatterns.push(/vine\.validate\(/);
        validationPatterns.push(/vine\.compile\(/);
      }
      if (validationImports.has('effect-schema')) {
        validationPatterns.push(/Schema\.decode\(/);
        validationPatterns.push(/Schema\.parse\(/);
        validationPatterns.push(/Schema\.decodeSync\(/);
        validationPatterns.push(/Schema\.parseSync\(/);
      }

      if (validationPatterns.some(pattern => pattern.test(text))) {
        hasValidation = true;
      }

      // Fix 15: Detect validation in called functions — function names that suggest validation
      if (ts.isIdentifier(n.expression) || ts.isPropertyAccessExpression(n.expression)) {
        const callName = ts.isIdentifier(n.expression) ? n.expression.text :
          (ts.isPropertyAccessExpression(n.expression) ? n.expression.name.text : '');
        const validationFuncPatterns = [
          /^validate/i, /^sanitize/i, /^check/i, /^verify/i,
          /Validation$/i, /Validator$/i, /Schema$/i,
          /^assertValid/i, /^ensureValid/i,
        ];
        if (validationFuncPatterns.some(p => p.test(callName))) {
          hasValidation = true;
        }
      }
    }

    // Fix 14: ORM implicit validation — TypeORM/class-validator decorators on entity classes
    // If we see @IsEmail, @IsString, @MinLength etc. decorators, the ORM validates on save
    if (ts.isDecorator(n)) {
      const decoratorText = n.getText();
      const ormValidationDecorators = [
        'IsEmail', 'IsString', 'IsNumber', 'IsBoolean', 'IsInt', 'IsDate',
        'MinLength', 'MaxLength', 'Min', 'Max', 'IsNotEmpty', 'IsOptional',
        'IsEnum', 'IsArray', 'IsUrl', 'IsUUID', 'Matches', 'ValidateNested',
        'IsPositive', 'IsNegative', 'Length', 'ArrayMinSize', 'ArrayMaxSize',
      ];
      if (ormValidationDecorators.some(d => decoratorText.includes(d))) {
        hasValidation = true;
      }
    }

    // NestJS DTO type checking — only counts when ValidationPipe is active
    if (hasValidationPipe && ts.isParameter(n)) {
      const typeNode = n.type;
      if (typeNode) {
        const typeText = typeNode.getText();
        if (!typeText.includes('any') && /[A-Z]/.test(typeText[0])) {
          hasValidation = true;
        }
      }
    }
  });

  return hasValidation;
}

// ──────────────────── Manual Validation Tracking ────────────────────

/**
 * Collect field names that have per-field manual validation.
 * Returns a map of field name → validation strength ('adequate' or 'weak').
 */
export function getManuallyValidatedFields(handlerNode: ts.Node): Map<string, 'adequate' | 'weak'> {
  const validated = new Map<string, 'adequate' | 'weak'>();
  const optPrefix = '(?:req(?:uest)?\\.(?:body|params|query)\\.|ctx\\.(?:request\\.body|params|query)\\.|request\\.(?:payload|params|query)\\.)?';

  const setAll = (regex: RegExp, text: string, strength: 'adequate' | 'weak') => {
    for (const m of text.matchAll(regex)) {
      const field = m[1];
      if (strength === 'adequate' || !validated.has(field)) {
        validated.set(field, strength);
      }
    }
  };

  traverse(handlerNode, (n) => {
    if (!ts.isIfStatement(n)) return;
    const condText = n.expression.getText();

    // typeof field === 'string' (adequate)
    setAll(new RegExp(`typeof\\s+${optPrefix}(\\w+)\\s*[!=]==?\\s*`, 'g'), condText, 'adequate');

    // Array.isArray(field) (adequate)
    setAll(new RegExp(`Array\\.isArray\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

    // field instanceof X (adequate)
    setAll(new RegExp(`${optPrefix}(\\w+)\\s+instanceof\\s+`, 'g'), condText, 'adequate');

    // Number.isInteger(field), Number.isFinite(field), Number.isNaN(field) (adequate)
    setAll(new RegExp(`Number\\.(?:isInteger|isFinite|isNaN)\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

    // ARRAY.includes(field) or SET.has(field) (adequate — allowlist)
    setAll(new RegExp(`\\.(?:includes|has)\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

    // field.match(/pattern/) or /pattern/.test(field) (adequate — regex validation)
    setAll(new RegExp(`${optPrefix}(\\w+)\\.match\\(`, 'g'), condText, 'adequate');
    setAll(new RegExp(`\\.test\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

    // field.length > N, field.trim().length > 0 (adequate)
    setAll(new RegExp(`${optPrefix}(\\w+)(?:\\.trim\\(\\))?\\.length\\s*[><=]`, 'g'), condText, 'adequate');

    // field > N, field < N, field >= N (adequate — range check)
    for (const m of condText.matchAll(new RegExp(`${optPrefix}(\\w+)\\s*[><=]+\\s*\\d`, 'g'))) {
      if (!m[0].includes('.length')) {
        validated.set(m[1], 'adequate');
      }
    }

    // Presence-only: !field or field == null (weak)
    setAll(new RegExp(`!${optPrefix}(\\w+)\\b`, 'g'), condText, 'weak');
    setAll(new RegExp(`${optPrefix}(\\w+)\\s*[!=]==?\\s*(?:null|undefined)\\b`, 'g'), condText, 'weak');
  });

  return validated;
}
