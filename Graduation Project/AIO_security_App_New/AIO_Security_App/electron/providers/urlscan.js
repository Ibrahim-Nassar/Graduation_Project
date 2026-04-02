import { createHttpClient, httpRequest } from '../net/http.js'

export async function urlscanLookup(url, apiKey, signal, onProgress) {
	const startTime = Date.now()
	const client = createHttpClient('https://urlscan.io/api/v1', apiKey ? { 'API-Key': apiKey } : undefined, 15000)
	if (onProgress) onProgress({ stage: 'analyzing', provider: 'urlscan', progress: 20 })
	try {
		const searchQuery = `url:\"${url}\"`
		const data = await httpRequest(client, { url: '/search/', method: 'GET', params: { q: searchQuery, size: 1 }, signal, __provider: 'urlscan' })
		const results = data?.results || []
		if (results.length === 0) {
			return { status: 'unknown', score: 0, evidence: ['no_reports_found=true'], raw_ref: undefined, latency_ms: Date.now() - startTime, cache_hit: false, details: { search_query: searchQuery, results_found: 0 } }
		}
		if (onProgress) onProgress({ stage: 'analyzing', provider: 'urlscan', progress: 80 })
		const result = results[0]
		const verdicts = result.verdicts || {}
		const overall = verdicts.overall || {}
		const score = overall.score || 0
		const tags = result.tags || []
		const resultUrl = result.result
		let status = 'unknown'
		if (overall.malicious || score >= 80) status = 'malicious'
		else if (overall.suspicious || score >= 40) status = 'suspicious'
		else if (overall.hasVerdicts === false || score === 0) status = 'clean'
		const evidence = [
			`verdict=${overall.categories ? overall.categories.join(',') : 'none'}`,
			`score=${score}`
		]
		const relevantTags = tags.slice(0, 5)
		if (relevantTags.length > 0) evidence.push(`tags=${relevantTags.join(',')}`)
		return { status, score, evidence, raw_ref: resultUrl, latency_ms: Date.now() - startTime, cache_hit: false, details: { verdicts: overall, score, tags: relevantTags, scan_date: result.task?.time, uuid: result.task?.uuid } }
	} catch (error) {
		if (error?.response?.status === 429) {
			throw new Error('Rate limit exceeded - consider adding an API key for higher limits')
		}
		throw error
	}
} 