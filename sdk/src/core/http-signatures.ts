/**
 * HTTP Message Signatures (RFC 9421) primitives: strict Structured Field
 * (RFC 8941) handling for `Signature-Input` / `Signature`, and the signature
 * base of RFC 9421 §2.5. Agent-DID's request profile is built on top of this
 * in `AgentIdentity`.
 *
 * Python parity: `agent_did_sdk.core.http_signatures`.
 */

/** An RFC 8941 bare item as used by signature parameters. */
export type SignatureParamValue = string | number | boolean | { token: string };

export interface SignatureInput {
  /** Covered component identifiers, in order (names only; component parameters are not supported). */
  components: string[];
  /** Signature parameters, in order. */
  params: Array<[string, SignatureParamValue]>;
}

export interface HttpRequestLike {
  method: string;
  url: string;
  /** Header fields; names are matched case-insensitively. */
  headers: Record<string, string | string[] | undefined>;
}

export class HttpSignatureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HttpSignatureError';
  }
}

const KEY = /^[a-z*][a-z0-9_\-.*]*$/u;
const TOKEN = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*$/u;

// ---------------------------------------------------------------------------
// Serialization (RFC 8941 §4.1)
// ---------------------------------------------------------------------------

function serializeString(value: string): string {
  if (!/^[\x20-\x7e]*$/u.test(value)) {
    throw new HttpSignatureError('Structured Field strings must be printable ASCII');
  }
  return `"${value.replace(/\\/gu, '\\\\').replace(/"/gu, '\\"')}"`;
}

function serializeBareItem(value: SignatureParamValue): string {
  if (typeof value === 'string') {
    return serializeString(value);
  }
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || Math.abs(value) > 999_999_999_999_999) {
      throw new HttpSignatureError('Structured Field integers must be integers of at most 15 digits');
    }
    return String(value);
  }
  if (typeof value === 'boolean') {
    return value ? '?1' : '?0';
  }
  if (!TOKEN.test(value.token)) {
    throw new HttpSignatureError(`Invalid Structured Field token: ${value.token}`);
  }
  return value.token;
}

function serializeParams(params: Array<[string, SignatureParamValue]>): string {
  return params
    .map(([name, value]) => {
      if (!KEY.test(name)) {
        throw new HttpSignatureError(`Invalid Structured Field key: ${name}`);
      }
      return value === true ? `;${name}` : `;${name}=${serializeBareItem(value)}`;
    })
    .join('');
}

/** Serializes a signature's inner list (the `@signature-params` value and the `Signature-Input` member). */
export function serializeSignatureInput(input: SignatureInput): string {
  return `(${input.components.map(serializeString).join(' ')})${serializeParams(input.params)}`;
}

export function serializeSignature(label: string, signature: Uint8Array): string {
  if (!KEY.test(label)) {
    throw new HttpSignatureError(`Invalid signature label: ${label}`);
  }
  return `${label}=:${Buffer.from(signature).toString('base64')}:`;
}

// ---------------------------------------------------------------------------
// Parsing (RFC 8941 §4.2), restricted to what Signature-Input / Signature use
// ---------------------------------------------------------------------------

class Parser {
  private index = 0;

  constructor(private readonly input: string) {}

  public parseDictionary<T>(parseMember: () => T): Map<string, T> {
    const result = new Map<string, T>();
    this.skipSpaces();
    while (!this.done()) {
      const key = this.parseKey();
      if (this.peek() !== '=') {
        throw new HttpSignatureError(`Dictionary member ${key} has no value`);
      }
      this.index += 1;
      result.set(key, parseMember());
      this.skipOws();
      if (this.done()) {
        break;
      }
      this.expect(',');
      this.skipOws();
      if (this.done()) {
        throw new HttpSignatureError('Trailing comma in dictionary');
      }
    }
    return result;
  }

  public parseInnerList(): SignatureInput {
    this.expect('(');
    const components: string[] = [];
    for (;;) {
      this.skipSpaces();
      if (this.peek() === ')') {
        this.index += 1;
        break;
      }
      components.push(this.parseString());
      if (this.peek() === ';') {
        throw new HttpSignatureError('Component identifier parameters are not supported');
      }
      if (this.peek() !== ' ' && this.peek() !== ')') {
        throw new HttpSignatureError('Malformed inner list');
      }
    }
    return { components, params: this.parseParams() };
  }

  public parseByteSequence(): Uint8Array {
    this.expect(':');
    const end = this.input.indexOf(':', this.index);
    if (end === -1) {
      throw new HttpSignatureError('Unterminated byte sequence');
    }
    const encoded = this.input.slice(this.index, end);
    if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(encoded) || encoded.length % 4 !== 0) {
      throw new HttpSignatureError('Invalid base64 in byte sequence');
    }
    this.index = end + 1;
    return new Uint8Array(Buffer.from(encoded, 'base64'));
  }

  private parseParams(): Array<[string, SignatureParamValue]> {
    const params: Array<[string, SignatureParamValue]> = [];
    while (this.peek() === ';') {
      this.index += 1;
      this.skipSpaces();
      const name = this.parseKey();
      let value: SignatureParamValue = true;
      if (this.peek() === '=') {
        this.index += 1;
        value = this.parseBareItem();
      }
      const existing = params.findIndex(([key]) => key === name);
      if (existing !== -1) {
        throw new HttpSignatureError(`Duplicate signature parameter: ${name}`);
      }
      params.push([name, value]);
    }
    return params;
  }

  private parseBareItem(): SignatureParamValue {
    const char = this.peek();
    if (char === '"') {
      return this.parseString();
    }
    if (char === '?') {
      const value = this.input.slice(this.index, this.index + 2);
      if (value !== '?0' && value !== '?1') {
        throw new HttpSignatureError('Invalid boolean');
      }
      this.index += 2;
      return value === '?1';
    }
    if (char === '-' || /[0-9]/u.test(char)) {
      const match = /^-?[0-9]{1,15}/u.exec(this.input.slice(this.index));
      if (!match || /^[.0-9]/u.test(this.input.charAt(this.index + match[0].length))) {
        throw new HttpSignatureError('Invalid integer (decimals are not used by signature parameters)');
      }
      this.index += match[0].length;
      return Number(match[0]);
    }
    const match = /^[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*/u.exec(this.input.slice(this.index));
    if (!match) {
      throw new HttpSignatureError('Invalid bare item');
    }
    this.index += match[0].length;
    return { token: match[0] };
  }

  private parseString(): string {
    this.expect('"');
    let output = '';
    for (;;) {
      if (this.done()) {
        throw new HttpSignatureError('Unterminated string');
      }
      const char = this.input.charAt(this.index);
      this.index += 1;
      if (char === '\\') {
        const next = this.input.charAt(this.index);
        if (next !== '"' && next !== '\\') {
          throw new HttpSignatureError('Invalid escape in string');
        }
        output += next;
        this.index += 1;
      } else if (char === '"') {
        return output;
      } else if (char < '\x20' || char > '\x7e') {
        throw new HttpSignatureError('Strings must be printable ASCII');
      } else {
        output += char;
      }
    }
  }

  private parseKey(): string {
    const match = /^[a-z*][a-z0-9_\-.*]*/u.exec(this.input.slice(this.index));
    if (!match) {
      throw new HttpSignatureError('Invalid dictionary or parameter key');
    }
    this.index += match[0].length;
    return match[0];
  }

  private expect(char: string): void {
    if (this.peek() !== char) {
      throw new HttpSignatureError(`Expected "${char}"`);
    }
    this.index += 1;
  }

  private peek(): string {
    return this.input.charAt(this.index);
  }

  private skipSpaces(): void {
    while (this.peek() === ' ') this.index += 1;
  }

  private skipOws(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.index += 1;
  }

  private done(): boolean {
    return this.index >= this.input.length;
  }
}

/** Parses a `Signature-Input` field value into its members (label → inner list). */
export function parseSignatureInputHeader(value: string): Map<string, SignatureInput> {
  const parser = new Parser(value.trim());
  return parser.parseDictionary(() => parser.parseInnerList());
}

/** Parses a `Signature` field value into its members (label → signature bytes). */
export function parseSignatureHeader(value: string): Map<string, Uint8Array> {
  const parser = new Parser(value.trim());
  return parser.parseDictionary(() => parser.parseByteSequence());
}

export function getSignatureParam(input: SignatureInput, name: string): SignatureParamValue | undefined {
  return input.params.find(([key]) => key === name)?.[1];
}

// ---------------------------------------------------------------------------
// Signature base (RFC 9421 §2.5)
// ---------------------------------------------------------------------------

function headerValue(request: HttpRequestLike, name: string): string {
  const values = Object.entries(request.headers)
    .filter(([key, value]) => key.toLowerCase() === name && value !== undefined)
    .flatMap(([, value]) => (Array.isArray(value) ? value : [value as string]));
  if (values.length === 0) {
    throw new HttpSignatureError(`Covered header field is missing: ${name}`);
  }
  // RFC 9421 §2.1: strip leading/trailing whitespace, join multiple field lines with ", ".
  const combined = values.map((value) => value.replace(/\r?\n[ \t]+/gu, ' ').trim()).join(', ');
  if (/[\r\n]/u.test(combined)) {
    throw new HttpSignatureError(`Header field ${name} contains line breaks`);
  }
  return combined;
}

function derivedComponentValue(request: HttpRequestLike, name: string): string {
  const url = new URL(request.url);
  switch (name) {
    case '@method':
      return request.method;
    case '@target-uri':
      return url.href;
    case '@authority':
      return url.host.toLowerCase();
    case '@scheme':
      return url.protocol.slice(0, -1).toLowerCase();
    case '@request-target':
      return `${url.pathname || '/'}${url.search}`;
    case '@path':
      return url.pathname || '/';
    case '@query':
      return url.search || '?';
    default:
      throw new HttpSignatureError(`Unsupported derived component: ${name}`);
  }
}

/** Builds the RFC 9421 signature base for `input` over `request`. */
export function buildSignatureBase(request: HttpRequestLike, input: SignatureInput): string {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const component of input.components) {
    if (seen.has(component)) {
      throw new HttpSignatureError(`Duplicate covered component: ${component}`);
    }
    seen.add(component);
    if (component !== component.toLowerCase()) {
      throw new HttpSignatureError(`Component names must be lowercase: ${component}`);
    }
    const value = component.startsWith('@')
      ? derivedComponentValue(request, component)
      : headerValue(request, component);
    lines.push(`${serializeString(component)}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeSignatureInput(input)}`);
  return lines.join('\n');
}
