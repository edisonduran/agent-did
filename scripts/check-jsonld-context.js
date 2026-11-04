#!/usr/bin/env node
/**
 * M-19: checks that the published Agent-DID JSON-LD context (contexts/v1.jsonld) is complete.
 *
 * Every Agent-DID document we ship (the did:webvh log vectors and the SDK-built documents) is
 * expanded in safe mode, which fails on any property or type the contexts do not define. The
 * context's SHA-256 is pinned in contexts/v1.jsonld.sha256 so that a published version is
 * immutable: change the context only by creating contexts/v2.jsonld.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const jsonld = require('jsonld');

const root = path.resolve(__dirname, '..');
const CONTEXT_URL = 'https://agent-did.org/v1';
const contextPath = path.join(root, 'contexts', 'v1.jsonld');
const contextBytes = fs.readFileSync(contextPath);
const contextDoc = JSON.parse(contextBytes.toString('utf8'));

const pinned = fs.readFileSync(`${contextPath}.sha256`, 'utf8').trim().split(/\s+/)[0];
const actual = crypto.createHash('sha256').update(contextBytes).digest('hex');
if (pinned !== actual) {
  console.error(`contexts/v1.jsonld changed (sha256 ${actual}) but the pin is ${pinned}.`);
  console.error('A published context is immutable. Add contexts/v2.jsonld instead of editing v1.');
  process.exit(1);
}

const defaultLoader = jsonld.documentLoaders.node();
const documentLoader = async (url) => {
  if (url === CONTEXT_URL) {
    return { contextUrl: null, documentUrl: url, document: contextDoc };
  }
  return defaultLoader(url);
};

// The did:webvh spec adds implicit services ("relativeRef", "LinkedVerifiablePresentation") that
// no JSON-LD context defines, upstream included. They are not Agent-DID terms, so they are left
// out of this check, which is about the terms this repository owns.
function withoutImplicitServices(document) {
  if (!Array.isArray(document.service)) return document;
  const IMPLICIT = new Set(['relativeRef', 'LinkedVerifiablePresentation']);
  return { ...document, service: document.service.filter((s) => !IMPLICIT.has(s.type)) };
}

function collectDocuments() {
  const documents = [];
  const vectors = JSON.parse(fs.readFileSync(path.join(root, 'fixtures', 'webvh-log-vectors.json'), 'utf8'));
  const seen = new Set();
  const visit = (value) => {
    if (Array.isArray(value)) value.forEach(visit);
    else if (value && typeof value === 'object') {
      if (
        Array.isArray(value['@context']) &&
        value['@context'].includes(CONTEXT_URL) &&
        typeof value.id === 'string' &&
        value.id.startsWith('did:') // skips the '{DID}' genesis templates
      ) {
        const text = JSON.stringify(value);
        if (!seen.has(text)) {
          seen.add(text);
          documents.push(withoutImplicitServices(value));
        }
      }
      Object.values(value).forEach(visit);
    }
  };
  visit(vectors);
  const extra = path.join(root, 'fixtures', 'jsonld-context-documents.json');
  if (fs.existsSync(extra)) visit(JSON.parse(fs.readFileSync(extra, 'utf8')));
  return documents;
}

async function main() {
  const documents = collectDocuments();
  if (documents.length === 0) {
    throw new Error('No Agent-DID documents found to check.');
  }
  let failures = 0;
  for (const [index, doc] of documents.entries()) {
    try {
      const expanded = await jsonld.expand(doc, { documentLoader, safe: true });
      const agentMetadata = expanded[0]['https://agent-did.org/vocab#agentMetadata'];
      if (!agentMetadata) throw new Error('agentMetadata did not expand to the agentdid vocabulary');
    } catch (error) {
      failures += 1;
      console.error(`document #${index} (${doc.id}): ${error.message}${error.details ? ' ' + JSON.stringify(error.details) : ''}`);
    }
  }
  if (failures > 0) process.exit(1);
  console.log(`JSON-LD context OK: ${documents.length} document(s) expand in safe mode; sha256 ${actual}.`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
