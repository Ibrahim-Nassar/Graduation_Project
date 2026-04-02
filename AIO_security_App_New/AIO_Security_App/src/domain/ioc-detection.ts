/**
 * Shared IOC Detection Logic
 * Used by both Frontend (React) and Backend (Electron)
 */

export const IOC_TYPE = {
	IP: 'ip',
	DOMAIN: 'domain',
	URL: 'url',
	HASH: 'hash',
	UNKNOWN: 'unknown'
} as const;

export type IocType = typeof IOC_TYPE[keyof typeof IOC_TYPE];

// Regex definitions
const IP_V4 = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})\b/g;
const IP_V6 = /\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b/ig;
// URL Regex: simplistic but effective for most cases. 
const URL_RE = /\bhttps?:\/\/[\w.-]+(?:\/[\w\-.~:/?#[\]@!$&'()*+,;=%]*)?/ig;
// Domain Regex: requires at least one dot, no leading/trailing dashes
const DOMAIN_RE = /\b(?=.{1,253}\b)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?\b/g;
// Hash Regex: MD5(32), SHA1(40), SHA256(64)
const HASH_RE = /\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b/ig;

/**
 * Detects the type of an Indicator of Compromise (IOC)
 */
export function detectIocType(value: unknown): IocType {
	const v = String(value || '').trim();
	if (!v) return IOC_TYPE.UNKNOWN;
	
	// IPv4 - strict validation
	if (/^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(v)) {
		return IOC_TYPE.IP;
	}
	
	// IPv6
	if (/^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(v)) {
		return IOC_TYPE.IP;
	}
	
	// URL
	try {
		const u = new URL(v);
		if (u.protocol === 'http:' || u.protocol === 'https:') {
			return IOC_TYPE.URL;
		}
	} catch {
		// Not a valid URL
	}
	
	// Domain
	if (/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$/.test(v)) {
		return IOC_TYPE.DOMAIN;
	}
	
	// Hash
	if (/^[a-f0-9]{32}$/i.test(v) || /^[a-f0-9]{40}$/i.test(v) || /^[a-f0-9]{64}$/i.test(v)) {
		return IOC_TYPE.HASH;
	}
	
	return IOC_TYPE.UNKNOWN;
}

export interface ParsedIOC {
	type: IocType;
	value: string;
	normalized: string;
}

export function parseIoc(value: unknown): ParsedIOC | null {
	const type = detectIocType(value);
	if (type === IOC_TYPE.UNKNOWN) {
		return null;
	}
	
	const valStr = String(value).trim();
	return {
		type,
		value: valStr,
		normalized: valStr.toLowerCase()
	};
}

function splitCsvSmart(text: string): string[] {
	// Split by newline first
	const lines = text.split(/\r?\n|\u2028|\u2029/);
	const tokens: string[] = [];
	for (const line of lines){
		// Split by common delimiters
		const parts = line.split(/[;,\t]/);
		for (const p of parts){
			const t = p.trim();
			if (t) tokens.push(t);
		}
	}
	return tokens;
}

export function extractIOCsFromText(input: string): string[] {
	const text = String(input || '');
	const found = new Set<string>();
	
	// 1. Tokenize (CSV/List style)
	const tokens = splitCsvSmart(text);
	for (const token of tokens){
		// Try direct match first
		const type = detectIocType(token);
		if (type !== IOC_TYPE.UNKNOWN) {
			found.add(token);
			continue;
		}
		
		// Try cleaning prefix "Type: Value"
		const valuePart = token.replace(/^\s*(type|ioc|indicator)\s*[:=,\s]+/i, '').trim();
		if (valuePart && valuePart !== token){
			if (detectIocType(valuePart) !== IOC_TYPE.UNKNOWN) {
				found.add(valuePart);
			}
		}
	}
	
	// 2. Scan full text for embedded IOCs (inline in logs etc)
	const regexes = [URL_RE, HASH_RE, IP_V4, IP_V6, DOMAIN_RE];
	for (const re of regexes){
		re.lastIndex = 0;
		let m;
		while ((m = re.exec(text)) !== null){
			const val = m[0];
			if (detectIocType(val) !== IOC_TYPE.UNKNOWN) {
				found.add(val);
			}
		}
	}
	
	return Array.from(found);
}

export function isValidIoc(value: unknown): boolean {
	return detectIocType(value) !== IOC_TYPE.UNKNOWN;
}

export interface IocContext {
  sourceLine: string;
  lineNumber: number;
  timestamp?: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  username?: string;
  hostname?: string;
  [key: string]: string | number | undefined;
}

export interface ExtractedIOCWithContext {
  value: string;
  type: IocType;
  context: IocContext;
}

/**
 * Extracts IOCs with their surrounding context (line content, line number)
 * Optionally accepts a custom parser for context
 */
export function extractIOCsWithContext(
  input: string, 
  contextParser?: (line: string) => Partial<IocContext>
): ExtractedIOCWithContext[] {
  const lines = String(input || '').split(/\r?\n/);
  const results: ExtractedIOCWithContext[] = [];
  const seen = new Set<string>();

  lines.forEach((line, index) => {
    const trimmedLine = line.trim();
    if (!trimmedLine) return;

    // Extract from this single line
    const iocs = extractIOCsFromText(line);
    
    for (const ioc of iocs) {
      // Deduplicate per call? 
      // Usually for a bulk scan we want all unique IOCs, 
      // but for "context extraction" we might want to know all places it appeared.
      // The requirement says "each IOC stores... Original source line".
      // If an IOC appears twice, we might want both contexts? 
      // But the main app flow keys by IOC value.
      // Let's skip duplicates for now to match existing behavior, 
      // or maybe keep the *first* context or merge them.
      // For now, first occurrence wins for simplicity in the list view.
      if (seen.has(ioc)) continue;
      seen.add(ioc);

      let extraContext: Partial<IocContext> = {};
      
      // Use custom parser if provided
      if (contextParser) {
        extraContext = contextParser(trimmedLine);
      } else {
        // Fallback heuristic
        const timeMatch = /\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/.exec(line);
        if (timeMatch) extraContext.timestamp = timeMatch[0];
      }

      results.push({
        value: ioc,
        type: detectIocType(ioc),
        context: {
          sourceLine: trimmedLine,
          lineNumber: index + 1,
          ...extraContext
        }
      });
    }
  });

  return results;
}
