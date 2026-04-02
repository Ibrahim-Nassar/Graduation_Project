/**
 * IOC Type enumeration
 */
export const IOC_TYPE = {
	IP: 'ip',
	DOMAIN: 'domain',
	URL: 'url',
	HASH: 'hash',
	UNKNOWN: 'unknown'
}

/**
 * Detects the type of an Indicator of Compromise (IOC)
 * @param {string} value - The IOC value to detect
 * @returns {string} One of: 'ip', 'domain', 'url', 'hash', 'unknown'
 */
export function detectIocType(value) {
	const v = String(value || '').trim()
	if (!v) return IOC_TYPE.UNKNOWN
	
	// IPv4 - strict validation
	if (/^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(v)) {
		return IOC_TYPE.IP
	}
	
	// IPv6 - basic validation (permissive for various formats)
	if (/^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(v)) {
		return IOC_TYPE.IP
	}
	
	// URL - must have http/https protocol
	try {
		const u = new URL(v)
		if (u.protocol === 'http:' || u.protocol === 'https:') {
			return IOC_TYPE.URL
		}
	} catch {
		// Not a valid URL, continue to other checks
	}
	
	// Domain - improved validation with TLD requirement
	// Requires at least one dot and valid domain format
	if (/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$/.test(v)) {
		return IOC_TYPE.DOMAIN
	}
	
	// Hash - MD5 (32), SHA1 (40), SHA256 (64)
	if (/^[a-f0-9]{32}$/i.test(v) || /^[a-f0-9]{40}$/i.test(v) || /^[a-f0-9]{64}$/i.test(v)) {
		return IOC_TYPE.HASH
	}
	
	return IOC_TYPE.UNKNOWN
}

/**
 * Validates if a value is a valid IOC
 * @param {string} value - The value to validate
 * @returns {boolean} True if valid IOC, false otherwise
 */
export function isValidIoc(value) {
	return detectIocType(value) !== IOC_TYPE.UNKNOWN
}

/**
 * Parses and normalizes an IOC
 * @param {string} value - The IOC value
 * @returns {{type: string, value: string, normalized: string} | null}
 */
export function parseIoc(value) {
	const type = detectIocType(value)
	if (type === IOC_TYPE.UNKNOWN) {
		return null
	}
	
	const normalized = String(value).trim().toLowerCase()
	
	return {
		type,
		value: String(value).trim(),
		normalized
	}
}

