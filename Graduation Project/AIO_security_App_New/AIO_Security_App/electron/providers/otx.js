import { createHttpClient, httpRequest } from '../net/http.js'

export async function otxLookup(value, type, apiKey, signal){
	if (!apiKey) throw new Error('Missing OTX API key')
	let path = ''
	if (type === 'ip') path = `/api/v1/indicators/IPv4/${encodeURIComponent(value)}/general`
	else if (type === 'domain') path = `/api/v1/indicators/domain/${encodeURIComponent(value)}/general`
	else if (type === 'hash') path = `/api/v1/indicators/file/${encodeURIComponent(value)}/general`
	else if (type === 'url') {
		try { const u = new URL(String(value)); value = u.hostname; type = 'domain'; path = `/api/v1/indicators/domain/${encodeURIComponent(value)}/general` } catch {}
	}
	if (!path) throw new Error('Unsupported type for OTX')
	const client = createHttpClient('https://otx.alienvault.com', { 'X-OTX-API-KEY': apiKey }, 20000)
	try{
		const data = await httpRequest(client, { url: path, method: 'GET', signal, __provider: 'otx' })
		const pulses = Number(data?.pulse_info?.count ?? 0)
		const reput = Number(data?.reputation ?? 0)
		let score = 0
		if (pulses > 0) score = Math.min(100, 20 + Math.min(80, pulses * 5))
		if (reput < 0) score = Math.max(score, Math.min(100, 50 + Math.abs(reput) * 5))
		let status = 'unknown'
		if (score >= 75) status = 'malicious'
		else if (score >= 35) status = 'suspicious'
		else if (score > 0) status = 'clean'
		else status = 'unknown'
		return { status, score, details: { pulses, reputation: reput } }
	}catch(error){
		const status = error?.response?.status
		if (status === 403) throw new Error('Invalid OTX API key or access denied')
		else if (status === 404) return { status: 'unknown', score: 0, details: { pulses: 0, reputation: 0 } }
		else if (status === 429) throw new Error('OTX API rate limit exceeded')
		throw new Error(`OTX API error: ${error.message}`)
	}
} 