/**
 * HTTP client with retry logic and rate limit tracking
 * @module electron/net/http
 */
import axios from 'axios'

const NETWORK = {
	defaultTimeoutMs: 20000,
	uploadTimeoutMs: 120000,
	pollIntervalMs: 5000,
	maxRetries: 4,
	initialBackoffMs: 400,
	maxBackoffMs: 8000,
}

/**
 * In-memory rate limit tracker keyed by provider name
 * @type {Map<string, {remaining?: number, resetAt?: number, lastSeen: number}>}
 */
const rateLimitState = new Map()

/**
 * Sleep for specified duration with abort signal support
 * @param {number} ms - Milliseconds to sleep
 * @param {AbortSignal} [signal] - Optional abort signal
 * @returns {Promise<void>}
 */
function sleep(ms, signal){
	return new Promise((resolve, reject) => {
		const t = setTimeout(resolve, ms)
		if (signal) {
			const onAbort = () => { 
				clearTimeout(t)
				reject(new DOMException('Aborted','AbortError'))
			}
			if (signal.aborted) onAbort()
			signal.addEventListener('abort', onAbort, { once: true })
		}
	})
}

function parseRetryAfter(header){
	if (!header) return null
	const secs = Number(header)
	if (!Number.isNaN(secs)) return Math.max(0, secs * 1000)
	const date = Date.parse(header)
	if (!Number.isNaN(date)) return Math.max(0, date - Date.now())
	return null
}

function updateRateLimit(provider, headers){
	if (!provider || !headers) return
	const h = {}
	for (const [k, v] of Object.entries(headers)){
		if (!v) continue
		h[String(k).toLowerCase()] = v
	}
	let remaining = undefined
	let resetAt = undefined
	if (h['x-ratelimit-remaining'] || h['x-rate-limit-remaining'] || h['ratelimit-remaining']){
		const val = h['x-ratelimit-remaining'] || h['x-rate-limit-remaining'] || h['ratelimit-remaining']
		const num = Number(Array.isArray(val) ? val[0] : String(val).split(',')[0])
		if (!Number.isNaN(num)) remaining = num
	}
	// VirusTotal specific
	if (h['x-app-rate-limit-remaining']){
		const s = String(h['x-app-rate-limit-remaining']) // e.g. "4;1, 1000;1d"
		const first = s.split(',')[0]
		const parts = first.split(';')
		const num = Number(parts[0])
		if (!Number.isNaN(num)) remaining = num
	}
	const retryAfter = parseRetryAfter(h['retry-after'])
	if (retryAfter != null){
		resetAt = Date.now() + retryAfter
	}
	rateLimitState.set(provider, {
		remaining,
		resetAt,
		lastSeen: Date.now(),
	})
}

export function createHttpClient(baseURL, defaultHeaders = {}, timeoutMs = NETWORK.defaultTimeoutMs){
	const instance = axios.create({ baseURL, headers: defaultHeaders, timeout: timeoutMs })
	return instance
}

/**
 * Make HTTP request with automatic retry logic
 * @param {import('axios').AxiosInstance} client - Axios client instance
 * @param {import('axios').AxiosRequestConfig & {__provider?: string}} config - Request config
 * @returns {Promise<any>} Response data
 * @throws {Error} If request fails after all retries
 */
export async function httpRequest(client, config){
	let attempt = 0
	let lastError
	const maxRetries = NETWORK.maxRetries
	const initialBackoff = NETWORK.initialBackoffMs
	const maxBackoff = NETWORK.maxBackoffMs
	const provider = config && config.__provider ? config.__provider : undefined
	
	while (attempt <= maxRetries){
		try{
			const resp = await client.request(config)
			// Update rate limit tracking from response headers
			try { 
				updateRateLimit(provider, resp.headers) 
			} catch (err) {
				// Non-critical error, continue
				if (provider) {
					console.warn(`Failed to update rate limits for ${provider}:`, err.message)
				}
			}
			return resp.data
		}catch(err){
			lastError = err
			
			// Try to update rate limits from error response
			try { 
				updateRateLimit(provider, err?.response?.headers) 
			} catch (updateErr) {
				// Ignore rate limit update errors
			}
			
			const status = err?.response?.status
			const code = err?.code
			
			// Determine if we should retry
			const shouldRetry = status === 429 || 
			                    (typeof status === 'number' && status >= 500) || 
			                    code === 'ECONNABORTED' || 
			                    code === 'ECONNRESET'
			
			if (!shouldRetry || attempt === maxRetries) {
				// Log final failure
				if (provider) {
					const errorMsg = err?.response?.data?.error?.message || err?.message || 'Unknown error'
					console.error(`[${provider}] Request failed after ${attempt} attempts: ${errorMsg}`)
				}
				break
			}
			
			// Calculate backoff with jitter
			const retryAfterHeader = err?.response?.headers?.['retry-after']
			const retryAfterMs = parseRetryAfter(retryAfterHeader)
			const baseDelay = retryAfterMs ?? Math.min(maxBackoff, initialBackoff * Math.pow(2, attempt))
			const jitter = Math.random() * baseDelay * 0.2
			const delay = Math.round(baseDelay + jitter)
			
			if (provider) {
				console.warn(`[${provider}] Retry ${attempt + 1}/${maxRetries} after ${delay}ms (status: ${status}, code: ${code})`)
			}
			
			await sleep(delay, config.signal)
			attempt++
		}
	}
	
	throw lastError
}

export function getRateLimitSnapshot(){
	const obj = {}
	for (const [k, v] of rateLimitState.entries()){
		obj[k] = v
	}
	return obj
}

export { NETWORK } 