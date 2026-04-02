export interface ProviderResult<TVerdict extends 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'error' = 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'error'> {
	verdict?: TVerdict
	score: number
	detailsUrl?: string
	raw: unknown
	meta?: Record<string, unknown>
}

export type ParsedIOC = {
	type: 'ip' | 'domain' | 'url' | 'hash'
	value: string
}

export interface Provider {
	name: string
	supports: { ip?: boolean; domain?: boolean; url?: boolean; hash?: boolean; file?: boolean }
	reputation?: (ioc: ParsedIOC, signal: AbortSignal) => Promise<ProviderResult>
	file?: (filePath: string, sha256?: string, signal?: AbortSignal) => Promise<ProviderResult>
	urlSandbox?: (url: string, signal?: AbortSignal) => Promise<ProviderResult>
} 