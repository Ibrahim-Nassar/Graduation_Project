/* @vitest-environment node */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createHttpClient, httpRequest, getRateLimitSnapshot } from '../../electron/net/http.js'
import axios from 'axios'

// Mock axios
vi.mock('axios')

describe('HTTP Client', () => {
	beforeEach(() => {
		vi.clearAllMocks()
	})

	describe('createHttpClient', () => {
		it('creates axios instance with correct config', () => {
			const mockCreate = vi.fn()
			vi.mocked(axios).create = mockCreate

			createHttpClient('https://api.example.com', { 'Authorization': 'Bearer token' }, 15000)

			expect(mockCreate).toHaveBeenCalledWith({
				baseURL: 'https://api.example.com',
				headers: { 'Authorization': 'Bearer token' },
				timeout: 15000
			})
		})

		it('uses default timeout when not specified', () => {
			const mockCreate = vi.fn()
			vi.mocked(axios).create = mockCreate

			createHttpClient('https://api.example.com')

			expect(mockCreate).toHaveBeenCalledWith(
				expect.objectContaining({
					timeout: 20000
				})
			)
		})
	})

	describe('httpRequest', () => {
		it('returns data on successful request', async () => {
			const mockClient = {
				request: vi.fn().mockResolvedValue({ 
					data: { result: 'success' },
					headers: {}
				})
			} as any

			const result = await httpRequest(mockClient, { url: '/test', method: 'GET' })

			expect(result).toEqual({ result: 'success' })
		})

		it('retries on 429 rate limit', async () => {
			const mockClient = {
				request: vi.fn()
					.mockRejectedValueOnce({ response: { status: 429, headers: {} }, code: null })
					.mockResolvedValueOnce({ data: { result: 'success' }, headers: {} })
			} as any

			const result = await httpRequest(mockClient, { url: '/test', method: 'GET' })

			expect(mockClient.request).toHaveBeenCalledTimes(2)
			expect(result).toEqual({ result: 'success' })
		})

		it('retries on 500 server error', async () => {
			const mockClient = {
				request: vi.fn()
					.mockRejectedValueOnce({ response: { status: 500, headers: {} }, code: null })
					.mockResolvedValueOnce({ data: { result: 'success' }, headers: {} })
			} as any

			const result = await httpRequest(mockClient, { url: '/test', method: 'GET' })

			expect(mockClient.request).toHaveBeenCalledTimes(2)
			expect(result).toEqual({ result: 'success' })
		})

		it('does not retry on 404', async () => {
			const mockClient = {
				request: vi.fn()
					.mockRejectedValue({ response: { status: 404, headers: {} }, code: null })
			} as any

			await expect(httpRequest(mockClient, { url: '/test', method: 'GET' }))
				.rejects.toThrow()

			expect(mockClient.request).toHaveBeenCalledTimes(1)
		})

		it('respects abort signal', async () => {
			const controller = new AbortController()
			const mockClient = {
				request: vi.fn().mockImplementation(() => {
					controller.abort()
					return Promise.reject(new DOMException('Aborted', 'AbortError'))
				})
			} as any

			await expect(httpRequest(mockClient, { url: '/test', method: 'GET', signal: controller.signal }))
				.rejects.toThrow('Aborted')
		})

		it('tracks rate limits from response headers', async () => {
			const mockClient = {
				request: vi.fn().mockResolvedValue({ 
					data: { result: 'success' },
					headers: {
						'x-ratelimit-remaining': '99'
					}
				})
			} as any

			await httpRequest(mockClient, { url: '/test', method: 'GET', __provider: 'test-provider' })

			const snapshot = getRateLimitSnapshot()
			expect(snapshot['test-provider']).toBeDefined()
			expect(snapshot['test-provider'].remaining).toBe(99)
		})

		it('handles VirusTotal rate limit headers', async () => {
			const mockClient = {
				request: vi.fn().mockResolvedValue({ 
					data: { result: 'success' },
					headers: {
						'x-app-rate-limit-remaining': '4;1'
					}
				})
			} as any

			await httpRequest(mockClient, { url: '/test', method: 'GET', __provider: 'virustotal' })

			const snapshot = getRateLimitSnapshot()
			expect(snapshot['virustotal']).toBeDefined()
			expect(snapshot['virustotal'].remaining).toBe(4)
		})

		it('throws after max retries', async () => {
			const mockClient = {
				request: vi.fn().mockRejectedValue({ response: { status: 500, headers: {} }, code: null })
			} as any

			await expect(httpRequest(mockClient, { url: '/test', method: 'GET' }))
				.rejects.toThrow()

			// maxRetries is 4, so should be called 5 times total (initial + 4 retries)
			expect(mockClient.request).toHaveBeenCalledTimes(5)
		})
	})

	describe('getRateLimitSnapshot', () => {
		it('returns empty object when no rate limits tracked', () => {
			const snapshot = getRateLimitSnapshot()
			expect(snapshot).toBeDefined()
			expect(typeof snapshot).toBe('object')
		})
	})
})

