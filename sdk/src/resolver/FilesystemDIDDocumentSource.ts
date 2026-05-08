import path from 'node:path';
import { AgentDIDDocument } from '../core/types';
import { DIDDocumentSource } from './types';

export interface FilesystemDIDDocumentSourceConfig {
  referenceToPath?: (documentRef: string) => string;
  referenceToPaths?: (documentRef: string) => string[];
}

export class FilesystemDIDDocumentSource implements DIDDocumentSource {
  private readonly referenceToPath: (documentRef: string) => string;
  private readonly referenceToPaths: ((documentRef: string) => string[]) | undefined;

  constructor(config: FilesystemDIDDocumentSourceConfig = {}) {
    this.referenceToPath = config.referenceToPath || ((documentRef) => documentRef);
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
        return JSON.parse(rawDocument) as AgentDIDDocument;
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