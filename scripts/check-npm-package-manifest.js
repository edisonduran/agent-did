#!/usr/bin/env node
/**
 * Fails when a publishable npm package would ship runtime dependency specs that
 * only resolve inside this monorepo (file:, link:, workspace:, portal:, relative
 * or absolute paths) or that bypass the registry (git, GitHub shorthands, URLs).
 *
 * It inspects the package.json inside the packed tarball, i.e. exactly what npm
 * publishes. devDependencies are ignored because consumers never install them.
 *
 * Usage:
 *   node scripts/check-npm-package-manifest.js <package-dir | tarball.tgz> [...]
 */

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const CHECKED_FIELDS = ['dependencies', 'peerDependencies', 'optionalDependencies'];
const NON_REGISTRY_SPEC = /^(file|link|workspace|portal|git|git\+[a-z]+|github|gitlab|bitbucket|https?):/i;
const PATH_SPEC = /^(\.{1,2}[\\/]|[\\/]|~[\\/]|[a-z]:[\\/])/i;
const GITHUB_SHORTHAND = /^[\w.-]+\/[\w.-]+(#.*)?$/;

function readPackageJsonFromTarball(tarballPath) {
  const tar = zlib.gunzipSync(fs.readFileSync(tarballPath));
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/s, '');
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '');
    const fullName = prefix ? `${prefix}/${name}` : name;
    const size = parseInt(header.subarray(124, 136).toString('utf8').replace(/\0.*$/s, '').trim() || '0', 8);
    const dataStart = offset + 512;
    if (fullName === 'package/package.json') {
      return JSON.parse(tar.subarray(dataStart, dataStart + size).toString('utf8'));
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  throw new Error(`package/package.json not found in ${tarballPath}`);
}

function packToTemp(packageDir) {
  const destination = fs.mkdtempSync(path.join(os.tmpdir(), 'npm-manifest-check-'));
  const output = execFileSync('npm', ['pack', '--json', '--pack-destination', destination], {
    cwd: packageDir,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    stdio: ['ignore', 'pipe', 'inherit']
  });
  const [{ filename }] = JSON.parse(output);
  return path.join(destination, filename);
}

function findViolations(manifest) {
  const violations = [];
  for (const field of CHECKED_FIELDS) {
    for (const [name, spec] of Object.entries(manifest[field] || {})) {
      const value = String(spec).trim();
      if (NON_REGISTRY_SPEC.test(value) || PATH_SPEC.test(value) || GITHUB_SHORTHAND.test(value)) {
        violations.push(`${field}.${name} = "${value}"`);
      }
    }
  }
  for (const name of manifest.bundleDependencies || manifest.bundledDependencies || []) {
    violations.push(`bundleDependencies includes "${name}"`);
  }
  return violations;
}

function main(targets) {
  if (targets.length === 0) {
    console.error('Usage: node scripts/check-npm-package-manifest.js <package-dir | tarball.tgz> [...]');
    return 2;
  }

  let failed = false;
  for (const target of targets) {
    const tarball = target.endsWith('.tgz') ? target : packToTemp(target);
    const manifest = readPackageJsonFromTarball(tarball);
    const violations = findViolations(manifest);
    if (violations.length > 0) {
      failed = true;
      console.error(`FAIL ${manifest.name}@${manifest.version} (${target}) ships non-registry dependency specs:`);
      for (const violation of violations) {
        console.error(`  - ${violation}`);
      }
    } else {
      console.log(`PASS ${manifest.name}@${manifest.version} (${target}): runtime dependencies resolve from the registry.`);
    }
  }
  return failed ? 1 : 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { findViolations, readPackageJsonFromTarball };
