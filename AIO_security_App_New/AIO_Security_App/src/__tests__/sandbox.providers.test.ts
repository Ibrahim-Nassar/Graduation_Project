/* @vitest-environment node */
import { describe, it, expect, vi } from 'vitest'

// Mock Node.js fs module
vi.mock('node:fs', () => ({
	default: {
		readFileSync: vi.fn(() => Buffer.from('fake file content')),
		statSync: vi.fn(() => ({ size: 1024 })),
		createReadStream: vi.fn(() => 'fake stream')
	}
}))

// Mock Node.js crypto module
vi.mock('node:crypto', () => ({
	default: {
		createHash: vi.fn(() => ({
			update: vi.fn(() => ({
				digest: vi.fn(() => 'fake-hash-12345')
			}))
		}))
	}
}))

// Mock the sandbox providers
vi.mock('../../electron/providers/virustotal.js', () => ({
	vtFileLookup: vi.fn(async () => ({
		status: 'malicious',
		score: 85,
		evidence: ['malicious=8', 'suspicious=2', 'harmless=75'],
		raw_ref: 'https://www.virustotal.com/gui/file/abc123',
		latency_ms: 1500,
		cache_hit: true
	}))
}))


vi.mock('../../electron/providers/metadefender.js', () => ({
	metadefenderLookup: vi.fn(async () => ({
		status: 'clean',
		score: 0,
		evidence: ['scan_all_result_i=0', 'engines_detected=0', 'progress=100%'],
		latency_ms: 8000,
		cache_hit: false
	}))
}))

vi.mock('../../electron/providers/urlscan.js', () => ({
	urlscanLookup: vi.fn(async () => ({
		status: 'malicious',
		score: 90,
		evidence: ['verdict=malicious', 'score=90', 'tags=phishing,malware'],
		raw_ref: 'https://urlscan.io/result/xyz789',
		latency_ms: 800,
		cache_hit: false
	}))
}))

// Import after mocking
// @ts-ignore JS module without types
import * as sandboxScan from '../../electron/providers/sandbox-scan.js'

describe('Sandbox Provider Tests', () => {
	it('should aggregate file analysis results correctly', async () => {
		const mockPayload = {
			type: 'file' as const,
			input: { path: '/test/malware.exe', name: 'malware.exe', size: 1024 },
			providers: {
				virustotal: true,
				metadefender: true,
				urlscan: false
			},
			settings: {
				preferReputationFirst: false,
				allowThirdPartyUploads: true
			},
			jobId: 'test-job-123'
		}

		const mockApiKeys = {
			virustotal: 'vt_test_key',
			metadefender: 'md_test_key'
		}

		const mockControllers: AbortController[] = []
		const progressEvents: any[] = []
		const mockOnProgress = (data: any) => progressEvents.push(data)

		const result = await sandboxScan.scanSandbox(
			mockPayload,
			mockApiKeys,
			mockControllers,
			mockOnProgress
		) as any

		// Should prioritize malicious status
		expect(result.status).toBe('malicious')
		
		// Should average scores (85 + 0) / 2 = 42.5, rounded to 43
		expect(result.score).toBe(43)
		
		// Should have file info
		expect(result.fileInfo).toBeDefined()
		expect(result.fileInfo?.name).toBe('malware.exe')
		expect(result.fileInfo?.size).toBe(1024)
		
		// Should have provider results
		expect(result.providers.virustotal).toBeDefined()
		expect(result.providers.metadefender).toBeDefined()
		expect(result.providers.urlscan).toBeUndefined()
		
		// Should generate appropriate verdict
		expect(result.verdict).toContain('2 providers analyzed')
		expect(result.verdict).toContain('flagged as malicious')
	})

	it('should handle URL analysis correctly', async () => {
		const mockPayload = {
			type: 'url' as const,
			input: 'https://malicious-site.com',
			providers: {
				virustotal: false,
				metadefender: false,
				urlscan: true
			},
			settings: {
				preferReputationFirst: true,
				allowThirdPartyUploads: false
			},
			jobId: 'test-url-job'
		}

		const mockApiKeys = {
			urlscan: 'us_test_key'
		}

		const result = await sandboxScan.scanSandbox(
			mockPayload,
			mockApiKeys,
			[],
			() => {}
		) as any

		expect(result.status).toBe('malicious')
		expect(result.score).toBe(90)
		expect(result.type).toBe('url')
		expect(result.input).toBe('https://malicious-site.com')
		expect(result.providers.urlscan).toBeDefined()
		expect(result.fileInfo).toBeUndefined()
	})

	it('should handle missing API keys gracefully', async () => {
		const mockPayload = {
			type: 'file' as const,
			input: { path: '/test/file.exe', name: 'file.exe', size: 512 },
			providers: {
				virustotal: true,
				metadefender: false,
				urlscan: false
			},
			settings: {
				preferReputationFirst: false,
				allowThirdPartyUploads: true
			},
			jobId: 'test-missing-keys'
		}

		// Missing API keys
		const mockApiKeys = {}

		const result = await sandboxScan.scanSandbox(
			mockPayload,
			mockApiKeys,
			[],
			() => {}
		) as any

		// Should still return a result even with errors
		expect(result.providers.virustotal?.status).toBe('error')
		expect(result.providers.virustotal?.error).toContain('API key required')
	})

	it('should respect upload consent settings', async () => {
		const mockPayload = {
			type: 'file' as const,
			input: { path: '/test/file.exe', name: 'file.exe', size: 512 },
			providers: {
				virustotal: false,
				metadefender: true,
				urlscan: false
			},
			settings: {
				preferReputationFirst: false,
				allowThirdPartyUploads: false // Upload not allowed
			},
			jobId: 'test-no-uploads'
		}

		const mockApiKeys = {
			metadefender: 'md_test_key'
		}

		const result = await sandboxScan.scanSandbox(
			mockPayload,
			mockApiKeys,
			[],
			() => {}
		) as any

		// MetaDefender should error due to upload restrictions
		expect(result.providers.metadefender?.status).toBe('error')
		expect(result.providers.metadefender?.error).toContain('Third-party uploads not allowed')
	})
}) 