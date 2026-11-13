import { assertAgentDidDocument } from '../core/document-guard';
import path from 'node:path';
import { AgentDIDDocument } from '../core/types';
import { DIDDocumentSource } from './types';

export interface FilesystemDIDDocumentSourceConfig {
  /** Directory the default mapping writes to: a reference becomes `<rootDirectory>/<reference with unsafe characters replaced by _>.json`. */
  rootDirectory?: string;
  /** Maps a reference to a path. Required unless `rootDirectory` or `referenceToPaths` is given: a reference is never used as a path as it is. */
  referenceToPath?: (documentRef: string) => string;
  referenceToPaths?: (documentRef: string) => string[];
}

/** The file name of a reference under `rootDirectory`: path separators, `..` and anything outside `[A-Za-z0-9._-]` are replaced. */
function safeFileName(documentRef: string): string {
  const name = documentRef.replace(/[^A-Za-z0-9._-]/gu, '_').replace(/^\.+/u, '_');
  return `${name || '_'}.json`;
}

export class FilesystemDIDDocumentSource implements DIDDocumentSource {
  private readonly referenceToPath: (documentRef: string) => string;
  private readonly referenceToPaths: ((documentRef: string) => string[]) | undefined;

  constructor(config: FilesystemDIDDocumentSourceConfig = {}) {
    const rootDirectory = config.rootDirectory;
    if (!config.referenceToPath && !config.referenceToPaths && !rootDirectory) {
      throw new TypeError(
        'FilesystemDIDDocumentSource needs rootDirectory, referenceToPath or referenceToPaths: a reference is not used as a path as it is'
      );
    }
    this.referenceToPath =
      config.referenceToPath || ((documentRef) => path.join(rootDirectory ?? '.', safeFileName(documentRef)));
    this.referenceToPaths = config.referenceToPaths;
  }

  public async getByReference(documentRef: string): Promise<AgentDIDDocument | null> {
    const fs = await import('node:fs/promises');
    const candidatePaths = this.resolveCandidatePaths(documentRef);
    const errors: string[] = [];
    let allMissing = true;

    for (const candidatePath of candidatePaths) {
      try {
        const rawDocument = await fs.readFile(candidatePath, 'utf8');
        allMissing = false;
        const parsed: unknown = JSON.parse(rawDocument);
        assertAgentDidDocument(parsed, `The file ${candidatePath}`);
        return parsed;
      } catch (error) {
        if (this.isMissingFile(error)) {
          continue;
        }

        allMissing = false;
        const message = error instanceof Error ? error.message : String(error);
        errors.push(`${candidatePath}: ${message}`);
      }
    }

    if (allMissing) {
      return null;
    }

    throw new Error(`Failed to read DID document from filesystem paths. ${errors.join(' | ')}`);
  }

  public async storeByReference(documentRef: string, document: AgentDIDDocument): Promise<void> {
    const fs = await import('node:fs/promises');
    const targetPath = this.resolvePrimaryPath(documentRef);
    await fs.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.writeFile(targetPath, JSON.stringify(document, null, 2), 'utf8');
  }

  public async getDidLogByReference(documentRef: string): Promise<string | null> {
    const fs = await import('node:fs/promises');
    const candidatePaths = this.resolveCandidatePaths(documentRef);
    const errors: string[] = [];
    let allMissing = true;

    for (const candidatePath of candidatePaths) {
      try {
        const didLog = await fs.readFile(candidatePath, 'utf8');
        allMissing = false;
        return didLog;
      } catch (error) {
        if (this.isMissingFile(error)) {
          continue;
        }

        allMissing = false;
        const message = error instanceof Error ? error.message : String(error);
        errors.push(`${candidatePath}: ${message}`);
      }
    }

    if (allMissing) {
      return null;
    }

    throw new Error(`Failed to read did:webvh DID log from filesystem paths. ${errors.join(' | ')}`);
  }

  public async storeDidLogByReference(documentRef: string, didLog: string): Promise<void> {
    const fs = await import('node:fs/promises');
    const targetPath = this.resolvePrimaryPath(documentRef);
    await fs.mkdir(path.dirname(targetPath), { recursive: true });
    await fs.writeFile(targetPath, didLog, 'utf8');
  }

  private resolveCandidatePaths(documentRef: string): string[] {
    if (this.referenceToPaths) {
      return this.referenceToPaths(documentRef);
    }

    return [this.referenceToPath(documentRef)];
  }

  private resolvePrimaryPath(documentRef: string): string {
    const candidatePaths = this.resolveCandidatePaths(documentRef);
    if (candidatePaths.length === 0) {
      throw new Error(`No filesystem path candidates configured for reference: ${documentRef}`);
    }

    return candidatePaths[0];
  }

  private isMissingFile(error: unknown): boolean {
    return typeof error === 'object' && error !== null && 'code' in error && (error as { code?: string }).code === 'ENOENT';
  }
}