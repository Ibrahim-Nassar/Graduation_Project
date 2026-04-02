/* @vitest-environment node */
import { describe, it, expect, vi } from 'vitest'
import * as scanMod from '../../electron/providers/scan.js'

// Mock all provider modules
vi.mock('../../electron/providers/virustotal.js', () => ({
	vtLookup: vi.fn()
}))
vi.mock('../../electron/providers/abuseipdb.js', () => ({
	abuseipdbLookup: vi.fn()
}))
vi.mock('../../electron/providers/otx.js', () => ({
	otxLookup: vi.fn()
}))
vi.mock('../../electron/providers/threatfox.js', () => ({
	threatfoxLookup: vi.fn()
}))

describe('scanWithProviders - Error Handling', () => {
	it('handles missing API keys gracefully', async () => {
		const results = await (scanMod as any).scanWithProviders(
			['8.8.8.8'],
			{ virustotal: true, abuseipdb: true },
			{}, // Empty API keys
			[],
			null
		)

		expect(results).toHaveLength(1)
		expect(results[0].providers.virustotal).toMatchObject({
			provider: 'virustotal',
			status: 'error',
			error: expect.stringContaining('Missing VirusTotal API key')
		})
		expect(results[0].providers.abuseipdb).toMatchObject({
			provider: 'abuseipdb',
			status: 'error',
			error: expect.stringContaining('Missing AbuseIPDB API key')
		})
	})

	it('handles invalid IOC types', async () => {
		const results = await (scanMod as any).scanWithProviders(
			['not-a-valid-ioc', 'also-invalid'],
			{ virustotal: true },
			{ virustotal: 'test-key' },
			[],
			null
		)

		expect(results).toHaveLength(2)
		expect(results[0].status).toBe('invalid')
		expect(results[1].status).toBe('invalid')
	})

	it('continues processing after provider errors', async () => {
		const { vtLookup } = await import('../../electron/providers/virustotal.js')
		const { abuseipdbLookup } = await import('../../electron/providers/abuseipdb.js')

		// Make one provider fail and one succeed
		vi.mocked(vtLookup).mockRejectedValueOnce(new Error('Network timeout'))
		vi.mocked(abuseipdbLookup).mockResolvedValueOnce({
			status: 'clean',
			score: 5,
			details: {}
		})

		const onProgress = vi.fn()
		const results = await (scanMod as any).scanWithProviders(
			['8.8.8.8'],
			{ virustotal: true, abuseipdb: true },
			{ virustotal: 'key1', abuseipdb: 'key2' },
			[],
			onProgress
		)

		expect(results).toHaveLength(1)
		expect(results[0].providers.virustotal.status).toBe('error')
		expect(results[0].providers.abuseipdb.status).toBe('clean')
		
		// Should still report progress for both
		expect(onProgress).toHaveBeenCalledWith(0, 'virustotal', expect.any(Object))
		expect(onProgress).toHaveBeenCalledWith(0, 'abuseipdb', expect.any(Object))
	})

	it('aggregates status correctly when some providers error', async () => {
		const { vtLookup } = await import('../../electron/providers/virustotal.js')
		const { abuseipdbLookup } = await import('../../electron/providers/abuseipdb.js')

		vi.mocked(vtLookup).mockRejectedValueOnce(new Error('API error'))
		vi.mocked(abuseipdbLookup).mockResolvedValueOnce({
			status: 'malicious',
			score: 90,
			details: {}
		})

		const results = await (scanMod as any).scanWithProviders(
			['8.8.8.8'],
			{ virustotal: true, abuseipdb: true },
			{ virustotal: 'key1', abuseipdb: 'key2' },
			[],
			null
		)

		// Should prioritize malicious status from successful provider
		expect(results[0].status).toBe('malicious')
		expect(results[0].score).toBeGreaterThan(0)
	})

	it('handles multiple IOCs with mixed results', async () => {
		const { vtLookup } = await import('../../electron/providers/virustotal.js')

		// First IOC succeeds, second fails
		vi.mocked(vtLookup)
			.mockResolvedValueOnce({ status: 'clean', score: 10, details: {} })
			.mockRejectedValueOnce(new Error('Rate limited'))

		const results = await (scanMod as any).scanWithProviders(
			['8.8.8.8', '1.1.1.1'],
			{ virustotal: true },
			{ virustotal: 'test-key' },
			[],
			null
		)

		expect(results).toHaveLength(2)
		expect(results[0].status).toBe('clean')
		expect(results[1].providers.virustotal.status).toBe('error')
	})

	it('calls progress callback for all provider events', async () => {
		const { vtLookup } = await import('../../electron/providers/virustotal.js')
		const { abuseipdbLookup } = await import('../../electron/providers/abuseipdb.js')

		vi.mocked(vtLookup).mockResolvedValueOnce({ status: 'clean', score: 5, details: {} })
		vi.mocked(abuseipdbLookup).mockResolvedValueOnce({ status: 'clean', score: 3, details: {} })

		const onProgress = vi.fn()
		await (scanMod as any).scanWithProviders(
			['8.8.8.8'],
			{ virustotal: true, abuseipdb: true },
			{ virustotal: 'key1', abuseipdb: 'key2' },
			[],
			onProgress
		)

		// Should be called twice (once for each provider)
		expect(onProgress).toHaveBeenCalledTimes(2)
		expect(onProgress).toHaveBeenCalledWith(0, 'virustotal', expect.objectContaining({ provider: 'virustotal' }))
		expect(onProgress).toHaveBeenCalledWith(0, 'abuseipdb', expect.objectContaining({ provider: 'abuseipdb' }))
	})

	it('respects abort signals for cancellation', async () => {
		const { vtLookup } = await import('../../electron/providers/virustotal.js')

		vi.mocked(vtLookup).mockImplementation(async (value, type, key, signal) => {
			return new Promise((resolve, reject) => {
				const timeout = setTimeout(() => resolve({ status: 'clean', score: 5, details: {} }), 1000)
				if (signal) {
					signal.addEventListener('abort', () => {
						clearTimeout(timeout)
						reject(new DOMException('Aborted', 'AbortError'))
					})
					if (signal.aborted) {
						clearTimeout(timeout)
						reject(new DOMException('Aborted', 'AbortError'))
					}
				}
			})
		})

		const controller = new AbortController()
		const controllers = [controller]

		// Abort before starting
		controller.abort()

		// Start scan with already aborted signal
		const scanPromise = (scanMod as any).scanWithProviders(
			['8.8.8.8'],
			{ virustotal: true },
			{ virustotal: 'test-key' },
			controllers,
			null
		)

		await expect(scanPromise).rejects.toThrow()
	})

	it('handles empty IOC list', async () => {
		const results = await (scanMod as any).scanWithProviders(
			[],
			{ virustotal: true },
			{ virustotal: 'test-key' },
			[],
			null
		)

		expect(results).toHaveLength(0)
	})

	it('handles malformed API keys without crashing', async () => {
		const results = await (scanMod as any).scanWithProviders(
			['8.8.8.8'],
			{ virustotal: true },
			{ virustotal: null }, // null API key
			[],
			null
		)

		expect(results).toHaveLength(1)
		expect(results[0].providers.virustotal.status).toBe('error')
	})

	it('only calls AbuseIPDB for IP addresses', async () => {
		const { abuseipdbLookup } = await import('../../electron/providers/abuseipdb.js')
		// Reset mock from previous tests
		vi.mocked(abuseipdbLookup).mockClear()
		vi.mocked(abuseipdbLookup).mockResolvedValue({ status: 'clean', score: 5, details: {} })

		const results = await (scanMod as any).scanWithProviders(
			['example.com'], // Domain, not IP
			{ abuseipdb: true },
			{ abuseipdb: 'test-key' },
			[],
			null
		)

		// AbuseIPDB should not be called for domains
		expect(abuseipdbLookup).not.toHaveBeenCalled()
		expect(results[0].providers.abuseipdb).toBeUndefined()
	})
})

