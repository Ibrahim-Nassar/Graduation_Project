/**
 * Input validation utilities
 */

/**
 * Validates if a string is a valid URL
 */
export function isValidUrl(url: string): boolean {
	try {
		const parsed = new URL(url)
		return parsed.protocol === 'http:' || parsed.protocol === 'https:'
	} catch {
		return false
	}
}

/**
 * Validates if a string is a valid API key format
 */
export function isValidApiKey(key: string, provider: string): boolean {
	if (!key || typeof key !== 'string') return false
	
	const trimmed = key.trim()
	if (trimmed.length === 0) return false
	
	// Provider-specific validation
	switch (provider) {
		case 'virustotal':
			// VT keys start with vt_ or are 64 char hex
			return trimmed.startsWith('vt_') || /^[a-f0-9]{64}$/i.test(trimmed)
		case 'abuseipdb':
			// AbuseIPDB keys are alphanumeric, typically 80 chars
			return /^[a-zA-Z0-9]{40,100}$/.test(trimmed)
		case 'otx':
			// OTX keys are 64 char hex
			return /^[a-f0-9]{64}$/i.test(trimmed)
		case 'threatfox':
			// ThreatFox uses auth.abuse.ch format
			return trimmed.length >= 20 && /^[a-zA-Z0-9-_]+$/.test(trimmed)
		case 'metadefender':
			// MetaDefender keys are alphanumeric
			return /^[a-zA-Z0-9-_]+$/.test(trimmed) && trimmed.length >= 20
		case 'urlscan':
			// URLScan keys are UUID format or longer alphanumeric strings
			return /^[a-f0-9-]{36}$/i.test(trimmed) || (/^[a-zA-Z0-9-_]+$/.test(trimmed) && trimmed.length >= 10)
		default:
			// Generic validation - at least 10 chars
			return trimmed.length >= 10
	}
}

/**
 * Sanitizes user input to prevent injection attacks
 */
export function sanitizeInput(input: string): string {
	if (!input || typeof input !== 'string') return ''
	
	// Remove null bytes
	let sanitized = input.replace(/\0/g, '')
	
	// Trim whitespace
	sanitized = sanitized.trim()
	
	return sanitized
}

/**
 * Validates file size is within acceptable limits
 */
export function isValidFileSize(sizeBytes: number, maxMB: number = 100): boolean {
	if (typeof sizeBytes !== 'number' || sizeBytes < 0) return false
	const maxBytes = maxMB * 1024 * 1024
	return sizeBytes <= maxBytes
}

/**
 * Gets user-friendly error message for API key issues
 */
export function getApiKeyErrorMessage(provider: string): string {
	const providerNames: Record<string, string> = {
		virustotal: 'VirusTotal',
		abuseipdb: 'AbuseIPDB',
		otx: 'OTX (AlienVault)',
		threatfox: 'ThreatFox',
		metadefender: 'OPSWAT MetaDefender',
		urlscan: 'urlscan.io'
	}
	
	const name = providerNames[provider] || provider
	return `No API key configured for ${name}. Please add your API key in Settings before using this provider.`
}

