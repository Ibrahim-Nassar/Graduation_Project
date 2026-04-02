/**
 * Formatting utilities for display purposes
 * @module src/utils/formatting
 */

/**
 * Country code to name fallback mapping
 * Used when Intl.DisplayNames is not available
 */
const COUNTRY_FALLBACK: Record<string, string> = {
	DE: 'Germany',
	DK: 'Denmark',
	US: 'United States',
	GB: 'United Kingdom',
	FR: 'France',
	ES: 'Spain',
	IT: 'Italy',
	CN: 'China',
	JP: 'Japan',
	RU: 'Russia',
	IN: 'India',
	BR: 'Brazil',
	CA: 'Canada',
	AU: 'Australia',
	NL: 'Netherlands',
	SE: 'Sweden',
	NO: 'Norway',
	FI: 'Finland',
	PL: 'Poland',
	CH: 'Switzerland',
	AT: 'Austria',
	BE: 'Belgium',
	KR: 'South Korea',
	MX: 'Mexico',
	AR: 'Argentina',
	ZA: 'South Africa'
}

/**
 * Converts ISO 3166-1 alpha-2 region code to full country name
 * @param code - Two-letter country code (e.g., 'US', 'GB')
 * @returns Full country name
 */
export function toCountryName(code: string): string {
	if (!code || typeof code !== 'string') return code

	try {
		// Use Intl.DisplayNames if available (modern browsers/Node.js)
		type DisplayNamesCtor = new (locales: string[], options: { type: 'region' }) => { 
			of: (region: string) => string | undefined 
		}
		const DisplayNames = (Intl as unknown as { DisplayNames?: DisplayNamesCtor }).DisplayNames
		
		if (DisplayNames) {
			const dn = new DisplayNames(['en'], { type: 'region' })
			const name = dn.of(String(code).toUpperCase())
			if (name) return name
		}
	} catch (err) {
		// Fallback if Intl.DisplayNames fails
	}

	// Use fallback mapping
	return COUNTRY_FALLBACK[String(code).toUpperCase()] || String(code)
}

/**
 * Converts ISO 3166-1 alpha-2 country code to emoji flag
 * @param code - Two-letter country code (e.g., 'US', 'GB')
 * @returns Flag emoji or empty string if invalid
 */
export function toFlagEmoji(code: string): string {
	if (!code || typeof code !== 'string') return ''
	
	const cc = String(code).toUpperCase()
	if (!/^[A-Z]{2}$/.test(cc)) return ''
	
	// Regional indicator symbols are offset from ASCII 'A' by this value
	const OFFSET = 127397
	const first = String.fromCodePoint(OFFSET + cc.charCodeAt(0))
	const second = String.fromCodePoint(OFFSET + cc.charCodeAt(1))
	
	return first + second
}

/**
 * Formats file size in human-readable format
 * @param bytes - Size in bytes
 * @returns Formatted string (e.g., "1.5 MB")
 */
export function formatFileSize(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
	
	if (bytes < 1024) return `${bytes} B`
	if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
	if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
	return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

/**
 * Formats a timestamp to a human-readable relative time
 * @param timestamp - Unix timestamp in milliseconds
 * @returns Relative time string (e.g., "2 hours ago")
 */
export function formatRelativeTime(timestamp: number): string {
	const now = Date.now()
	const diff = now - timestamp
	const seconds = Math.floor(diff / 1000)
	const minutes = Math.floor(seconds / 60)
	const hours = Math.floor(minutes / 60)
	const days = Math.floor(hours / 24)

	if (days > 0) return `${days} day${days !== 1 ? 's' : ''} ago`
	if (hours > 0) return `${hours} hour${hours !== 1 ? 's' : ''} ago`
	if (minutes > 0) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`
	if (seconds > 10) return `${seconds} seconds ago`
	return 'just now'
}

/**
 * Truncates text to specified length with ellipsis
 * @param text - Text to truncate
 * @param maxLength - Maximum length before truncation
 * @returns Truncated text with ellipsis if needed
 */
export function truncateText(text: string, maxLength: number): string {
	if (!text || text.length <= maxLength) return text
	return text.slice(0, maxLength - 3) + '...'
}

