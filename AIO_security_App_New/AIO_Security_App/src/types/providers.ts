export type ProviderVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error'

export interface NormalizedProviderResult<TDetails = unknown> {
	provider: 'virustotal' | 'abuseipdb' | 'otx' | 'threatfox' | 'metadefender' | 'urlscan'
	status: ProviderVerdict
	score: number
	details?: TDetails
	error?: string
	latency_ms?: number
	cache_hit?: boolean
	evidence?: string[]
	raw_ref?: string
} 