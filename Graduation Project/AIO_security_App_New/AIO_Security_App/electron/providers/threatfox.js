import { createHttpClient, httpRequest } from '../net/http.js'

export async function threatfoxLookup(value, type, apiKey, signal){
	if (!apiKey) {
		throw new Error('ThreatFox API key required. Get one free at auth.abuse.ch')
	}
	const client = createHttpClient('https://threatfox-api.abuse.ch/api/v1/', { 'Auth-Key': apiKey, 'Content-Type': 'application/json' }, 20000)
	try{
		const data = await httpRequest(client, {
			url: '/',
			method: 'POST',
			data: { query: 'search_ioc', search_term: String(value), exact_match: type !== 'ip' },
			signal,
			__provider: 'threatfox'
		})
		if (data?.query_status !== 'ok'){
			if (data?.query_status === 'no_result') {
				return { status: 'unknown', score: 0, details: { count: 0 } }
			}
			return { status: 'unknown', score: 0, details: { query_status: data?.query_status } }
		}
		const entries = Array.isArray(data?.data) ? data.data : []
		if (entries.length === 0) return { status: 'unknown', score: 0, details: { count: 0 } }
		let relevantEntries = entries
		if (type === 'ip') {
			const ipValue = String(value)
			relevantEntries = entries.filter(entry => {
				const ioc = entry.ioc || ''
				return ioc === ipValue || ioc.startsWith(`${ipValue}:`)
			})
		}
		if (relevantEntries.length === 0) return { status: 'unknown', score: 0, details: { count: 0 } }
		const confidences = relevantEntries.map(e => Number(e?.confidence_level ?? 0)).filter(n => !Number.isNaN(n))
		const avg = confidences.length ? Math.round(confidences.reduce((a,b)=>a+b,0)/confidences.length) : 50
		let status = 'suspicious'
		if (avg >= 80) status = 'malicious'
		else if (avg >= 50) status = 'suspicious'
		else status = 'clean'
		return { status, score: avg, details: { count: relevantEntries.length, confidences, foundIOCs: relevantEntries.map(e => e.ioc).slice(0,3) } }
	}catch(error){
		const status = error?.response?.status
		if (status === 401 || status === 403) throw new Error('Invalid ThreatFox API key or access denied')
		else if (status === 429) throw new Error('ThreatFox API rate limit exceeded')
		else if (status >= 500) throw new Error('ThreatFox service temporarily unavailable')
		throw new Error(`ThreatFox API error: ${error.message}`)
	}
} 