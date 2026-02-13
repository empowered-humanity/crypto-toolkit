#!/usr/bin/env node

/**
 * CLI for crypto-toolkit
 */

import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';
import chalk from 'chalk';
import {
  encryptCombined,
  decryptCombined,
  generateKey,
} from './core/aead.js';
import { hashPassword, verifyPassword } from './core/password.js';
import { generateKeyPair, sign, verify } from './asymmetric/ed25519.js';
import { generateX25519KeyPair } from './asymmetric/x25519.js';
import { randomBytes, randomToken, randomUUID } from './core/random.js';
import { hashToHex } from './core/hash.js';

const program = new Command();

program
  .name('te-crypto')
  .description('Cryptographic toolkit CLI')
  .version('0.1.0');

// ============================================================================
// Encryption Commands
// ============================================================================

program
  .command('encrypt')
  .description('Encrypt a file')
  .requiredOption('-f, --file <path>', 'File to encrypt')
  .requiredOption('-k, --key-file <path>', 'Key file (32 bytes)')
  .requiredOption('-o, --output <path>', 'Output file')
  .action((options) => {
    try {
      const plaintext = readFileSync(resolve(options.file));
      const key = readFileSync(resolve(options.keyFile));

      if (key.length !== 32) {
        console.error(chalk.red('Error: Key must be 32 bytes'));
        process.exit(1);
      }

      const encrypted = encryptCombined(plaintext, key);
      writeFileSync(resolve(options.output), encrypted);

      console.log(chalk.green('✓ File encrypted successfully'));
      console.log(chalk.gray(`Input: ${options.file}`));
      console.log(chalk.gray(`Output: ${options.output}`));
      console.log(chalk.gray(`Size: ${plaintext.length} → ${encrypted.length} bytes`));
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

program
  .command('decrypt')
  .description('Decrypt a file')
  .requiredOption('-f, --file <path>', 'File to decrypt')
  .requiredOption('-k, --key-file <path>', 'Key file (32 bytes)')
  .requiredOption('-o, --output <path>', 'Output file')
  .action((options) => {
    try {
      const encrypted = readFileSync(resolve(options.file));
      const key = readFileSync(resolve(options.keyFile));

      if (key.length !== 32) {
        console.error(chalk.red('Error: Key must be 32 bytes'));
        process.exit(1);
      }

      const decrypted = decryptCombined(encrypted, key);
      writeFileSync(resolve(options.output), decrypted);

      console.log(chalk.green('✓ File decrypted successfully'));
      console.log(chalk.gray(`Input: ${options.file}`));
      console.log(chalk.gray(`Output: ${options.output}`));
      console.log(chalk.gray(`Size: ${encrypted.length} → ${decrypted.length} bytes`));
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ============================================================================
// Key Generation Commands
// ============================================================================

program
  .command('keygen')
  .description('Generate a cryptographic key')
  .requiredOption('-t, --type <type>', 'Key type (aes256, ed25519, x25519)')
  .requiredOption('-o, --output <path>', 'Output directory')
  .action(async (options) => {
    try {
      const outputDir = resolve(options.output);

      switch (options.type) {
        case 'aes256': {
          const key = generateKey();
          writeFileSync(`${outputDir}/key.bin`, key);
          console.log(chalk.green('✓ AES-256 key generated'));
          console.log(chalk.gray(`File: ${outputDir}/key.bin`));
          break;
        }

        case 'ed25519': {
          const keyPair = generateKeyPair();
          writeFileSync(`${outputDir}/ed25519_public.key`, keyPair.publicKey);
          writeFileSync(`${outputDir}/ed25519_private.key`, keyPair.secretKey);
          console.log(chalk.green('✓ Ed25519 key pair generated'));
          console.log(chalk.gray(`Public: ${outputDir}/ed25519_public.key`));
          console.log(chalk.gray(`Private: ${outputDir}/ed25519_private.key`));
          break;
        }

        case 'x25519': {
          const keyPair = generateX25519KeyPair();
          writeFileSync(`${outputDir}/x25519_public.key`, keyPair.publicKey);
          writeFileSync(`${outputDir}/x25519_private.key`, keyPair.secretKey);
          console.log(chalk.green('✓ X25519 key pair generated'));
          console.log(chalk.gray(`Public: ${outputDir}/x25519_public.key`));
          console.log(chalk.gray(`Private: ${outputDir}/x25519_private.key`));
          break;
        }

        default:
          console.error(chalk.red(`Error: Unknown key type: ${options.type}`));
          console.error(chalk.gray('Valid types: aes256, ed25519, x25519'));
          process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ============================================================================
// Password Commands
// ============================================================================

program
  .command('hash-password <password>')
  .description('Hash a password using Argon2id')
  .action(async (password: string) => {
    try {
      const hashed = await hashPassword(password);
      console.log(chalk.green('✓ Password hashed'));
      console.log(chalk.gray('Hash:'));
      console.log(hashed.hash);
      console.log(chalk.gray('\nParameters:'));
      console.log(`  Memory: ${Math.round(hashed.parameters.memoryCost / 1024)} MB`);
      console.log(`  Iterations: ${hashed.parameters.timeCost}`);
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

program
  .command('verify-password <password> <hash>')
  .description('Verify a password against a hash')
  .action(async (password: string, hash: string) => {
    try {
      const isValid = await verifyPassword(password, hash);

      if (isValid) {
        console.log(chalk.green('✓ Password is valid'));
        process.exit(0);
      } else {
        console.log(chalk.red('✗ Password is invalid'));
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ============================================================================
// Signing Commands
// ============================================================================

program
  .command('sign')
  .description('Sign a file with Ed25519')
  .requiredOption('-f, --file <path>', 'File to sign')
  .requiredOption('-k, --key <path>', 'Private key file')
  .requiredOption('-o, --output <path>', 'Output signature file')
  .action((options) => {
    try {
      const data = readFileSync(resolve(options.file));
      const privateKey = readFileSync(resolve(options.key));

      if (privateKey.length !== 64) {
        console.error(chalk.red('Error: Private key must be 64 bytes'));
        process.exit(1);
      }

      const signature = sign(data, privateKey);
      writeFileSync(resolve(options.output), signature);

      console.log(chalk.green('✓ File signed successfully'));
      console.log(chalk.gray(`File: ${options.file}`));
      console.log(chalk.gray(`Signature: ${options.output}`));
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

program
  .command('verify')
  .description('Verify a signature')
  .requiredOption('-f, --file <path>', 'File to verify')
  .requiredOption('-s, --sig <path>', 'Signature file')
  .requiredOption('-k, --key <path>', 'Public key file')
  .action((options) => {
    try {
      const data = readFileSync(resolve(options.file));
      const signature = readFileSync(resolve(options.sig));
      const publicKey = readFileSync(resolve(options.key));

      if (publicKey.length !== 32) {
        console.error(chalk.red('Error: Public key must be 32 bytes'));
        process.exit(1);
      }

      if (signature.length !== 64) {
        console.error(chalk.red('Error: Signature must be 64 bytes'));
        process.exit(1);
      }

      const isValid = verify(data, signature, publicKey);

      if (isValid) {
        console.log(chalk.green('✓ Signature is valid'));
        process.exit(0);
      } else {
        console.log(chalk.red('✗ Signature is invalid'));
        process.exit(1);
      }
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

// ============================================================================
// Utility Commands
// ============================================================================

program
  .command('random')
  .description('Generate random data')
  .option('-b, --bytes <number>', 'Number of bytes', '32')
  .option('-f, --format <format>', 'Output format (hex, base64, uuid, token)', 'hex')
  .action((options) => {
    try {
      const bytes = parseInt(options.bytes, 10);

      if (isNaN(bytes) || bytes <= 0) {
        console.error(chalk.red('Error: Bytes must be a positive number'));
        process.exit(1);
      }

      let output: string;

      switch (options.format) {
        case 'hex':
          output = Buffer.from(randomBytes(bytes)).toString('hex');
          break;
        case 'base64':
          output = Buffer.from(randomBytes(bytes)).toString('base64');
          break;
        case 'uuid':
          output = randomUUID();
          break;
        case 'token':
          output = randomToken(bytes);
          break;
        default:
          console.error(chalk.red(`Error: Unknown format: ${options.format}`));
          process.exit(1);
      }

      console.log(output);
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

program
  .command('hash')
  .description('Hash a file')
  .requiredOption('-f, --file <path>', 'File to hash')
  .option('-a, --algorithm <algorithm>', 'Hash algorithm (sha256, blake2b)', 'sha256')
  .action((options) => {
    try {
      const data = readFileSync(resolve(options.file));
      const hash = hashToHex(data, options.algorithm as 'sha256' | 'blake2b');

      console.log(chalk.green(`${options.algorithm.toUpperCase()}:`));
      console.log(hash);
    } catch (error) {
      console.error(chalk.red('Error:'), (error as Error).message);
      process.exit(1);
    }
  });

program.parse();
