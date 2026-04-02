import { describe, it, expect } from 'vitest'
import { 
	isValidUrl, 
	isValidApiKey, 
	sanitizeInput, 
	isValidFileSize,
	getApiKeyErrorMessage 
} from '../utils/validation'

describe('Validation Utilities', () => {
	describe('isValidUrl', () => {
		it('validates HTTP URLs', () => {
			expect(isValidUrl('http://example.com')).toBe(true)
			expect(isValidUrl('http://example.com/path')).toBe(true)
		})

		it('validates HTTPS URLs', () => {
			expect(isValidUrl('https://example.com')).toBe(true)
			expect(isValidUrl('https://example.com/path?query=value')).toBe(true)
		})

		it('rejects invalid URLs', () => {
			expect(isValidUrl('not a url')).toBe(false)
			expect(isValidUrl('ftp://example.com')).toBe(false)
			expect(isValidUrl('')).toBe(false)
		})
	})

	describe('isValidApiKey', () => {
		it('validates VirusTotal API keys', () => {
			expect(isValidApiKey('vt_abc123def456', 'virustotal')).toBe(true)
			expect(isValidApiKey('a'.repeat(64), 'virustotal')).toBe(true)
			expect(isValidApiKey('short', 'virustotal')).toBe(false)
		})

		it('validates AbuseIPDB API keys', () => {
			expect(isValidApiKey('a'.repeat(80), 'abuseipdb')).toBe(true)
			expect(isValidApiKey('short', 'abuseipdb')).toBe(false)
			expect(isValidApiKey('contains spaces', 'abuseipdb')).toBe(false)
		})

		it('validates OTX API keys', () => {
			expect(isValidApiKey('a'.repeat(64), 'otx')).toBe(true)
			expect(isValidApiKey('short', 'otx')).toBe(false)
		})

		it('validates ThreatFox API keys', () => {
			expect(isValidApiKey('a'.repeat(30), 'threatfox')).toBe(true)
			expect(isValidApiKey('short', 'threatfox')).toBe(false)
		})

		it('validates MetaDefender API keys', () => {
			expect(isValidApiKey('a'.repeat(30), 'metadefender')).toBe(true)
			expect(isValidApiKey('short', 'metadefender')).toBe(false)
		})

		it('validates URLScan API keys', () => {
			expect(isValidApiKey('550e8400-e29b-41d4-a716-446655440000', 'urlscan')).toBe(true)
			expect(isValidApiKey('a'.repeat(30), 'urlscan')).toBe(true)
			expect(isValidApiKey('short', 'urlscan')).toBe(false)
		})

		it('rejects empty or invalid keys', () => {
			expect(isValidApiKey('', 'virustotal')).toBe(false)
			expect(isValidApiKey('   ', 'virustotal')).toBe(false)
		})

		it('uses generic validation for unknown providers', () => {
			expect(isValidApiKey('a'.repeat(10), 'unknown-provider')).toBe(true)
			expect(isValidApiKey('short', 'unknown-provider')).toBe(false)
		})
	})

	describe('sanitizeInput', () => {
		it('removes null bytes', () => {
			expect(sanitizeInput('hello\x00world')).toBe('helloworld')
		})

		it('trims whitespace', () => {
			expect(sanitizeInput('  hello world  ')).toBe('hello world')
		})

		it('handles empty input', () => {
			expect(sanitizeInput('')).toBe('')
			expect(sanitizeInput('   ')).toBe('')
		})

		it('returns empty string for null/undefined', () => {
			expect(sanitizeInput(null as any)).toBe('')
			expect(sanitizeInput(undefined as any)).toBe('')
		})
	})

	describe('isValidFileSize', () => {
		it('validates file sizes within limits', () => {
			expect(isValidFileSize(1024 * 1024, 100)).toBe(true) // 1 MB
			expect(isValidFileSize(50 * 1024 * 1024, 100)).toBe(true) // 50 MB
			expect(isValidFileSize(100 * 1024 * 1024, 100)).toBe(true) // 100 MB
		})

		it('rejects file sizes over limit', () => {
			expect(isValidFileSize(101 * 1024 * 1024, 100)).toBe(false) // 101 MB
			expect(isValidFileSize(200 * 1024 * 1024, 100)).toBe(false) // 200 MB
		})

		it('uses default 100MB limit', () => {
			expect(isValidFileSize(50 * 1024 * 1024)).toBe(true)
			expect(isValidFileSize(150 * 1024 * 1024)).toBe(false)
		})

		it('rejects invalid sizes', () => {
			expect(isValidFileSize(-1, 100)).toBe(false)
			expect(isValidFileSize(NaN, 100)).toBe(false)
		})

		it('accepts zero-sized files', () => {
			expect(isValidFileSize(0, 100)).toBe(true)
		})
	})

	describe('getApiKeyErrorMessage', () => {
		it('returns friendly error messages for known providers', () => {
			expect(getApiKeyErrorMessage('virustotal')).toContain('VirusTotal')
			expect(getApiKeyErrorMessage('abuseipdb')).toContain('AbuseIPDB')
			expect(getApiKeyErrorMessage('otx')).toContain('OTX')
			expect(getApiKeyErrorMessage('threatfox')).toContain('ThreatFox')
			expect(getApiKeyErrorMessage('metadefender')).toContain('OPSWAT MetaDefender')
			expect(getApiKeyErrorMessage('urlscan')).toContain('urlscan.io')
		})

		it('returns generic message for unknown providers', () => {
			const message = getApiKeyErrorMessage('unknown-provider')
			expect(message).toContain('unknown-provider')
			expect(message).toContain('Settings')
		})

		it('includes instruction to add key in Settings', () => {
			const message = getApiKeyErrorMessage('virustotal')
			expect(message.toLowerCase()).toContain('settings')
		})
	})
})

