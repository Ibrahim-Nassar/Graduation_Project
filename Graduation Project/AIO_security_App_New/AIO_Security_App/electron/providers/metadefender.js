import fs from 'node:fs'
import FormData from 'form-data'
import { createHttpClient, httpRequest } from '../net/http.js'

export async function metadefenderLookup(filePath, apiKey, signal, onProgress) {
	if (!apiKey) throw new Error('Missing OPSWAT MetaDefender API key')
	const client = createHttpClient('https://api.metadefender.com/v4', { 'apikey': apiKey }, 30000)
	if (onProgress) onProgress({ stage: 'uploading', provider: 'metadefender', progress: 10 })
	const form = new FormData()
	form.append('file', fs.createReadStream(filePath))
	const upload = await httpRequest(client, { url: '/file', method: 'POST', data: form, headers: form.getHeaders(), timeout: 120000, signal, __provider: 'metadefender' })
	const dataId = upload?.data_id
	if (!dataId) throw new Error('Failed to get data ID from MetaDefender upload')
	if (onProgress) onProgress({ stage: 'analyzing', provider: 'metadefender', progress: 30 })
	let attempts = 0
	const maxAttempts = 60
	while (attempts < maxAttempts) {
		try {
			const resp = await httpRequest(client, { url: `/file/${dataId}`, method: 'GET', signal, __provider: 'metadefender' })
			const status = resp?.scan_results?.progress_percentage || 0
			if (onProgress) onProgress({ stage: 'analyzing', provider: 'metadefender', progress: Math.min(95, status) })
			if (resp?.scan_results?.scan_all_result_a !== undefined) {
				const result = String(resp.scan_results.scan_all_result_a)
				const enginesDetected = Number(resp.scan_results.total_detected_avs || 0)
				const score = Math.min(100, enginesDetected * 5)
				let normalized = 'unknown'
				if (result === 'No Threat Detected') normalized = 'clean'
				else if (/Found/i.test(result)) normalized = 'malicious'
				else if (/Suspicious/i.test(result)) normalized = 'suspicious'
				return {
					status: normalized,
					score,
					evidence: [
						`scan_all_result_a=${result}`,
						`engines_detected=${enginesDetected}`
					],
					latency_ms: undefined,
					cache_hit: false
				}
			}
		} catch (err) {
			// continue
		}
		await new Promise(r => setTimeout(r, 10000))
		attempts++
	}
	throw new Error('MetaDefender analysis timeout')
} 