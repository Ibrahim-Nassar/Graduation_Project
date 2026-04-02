import { createHttpClient, httpRequest } from '../net/http.js'

export async function abuseipdbLookup(ip, apiKey, signal){
	if (!apiKey) throw new Error('Missing AbuseIPDB API key')
	
	// Validate that the input is actually an IP address
	const ipStr = String(ip || '').trim()
	
	// IPv4 validation
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/
	// IPv6 validation (basic)
	const ipv6Regex = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i
	
	if (!ipv4Regex.test(ipStr) && !ipv6Regex.test(ipStr)) {
		throw new Error(`AbuseIPDB only accepts IP addresses. Received: "${ipStr}" which is not a valid IP.`)
	}
	
	const client = createHttpClient('https://api.abuseipdb.com/api/v2', { 'Key': apiKey, 'Accept': 'application/json' }, 15000)
	const data = await httpRequest(client, {
		url: '/check',
		method: 'GET',
		params: { ipAddress: ipStr, maxAgeInDays: 365 },
		signal,
		__provider: 'abuseipdb'
	})
	const d = data?.data || {}
	const score = Number(d.abuseConfidenceScore ?? 0)
	let status = 'unknown'
	if (score >= 75) status = 'malicious'
	else if (score >= 25) status = 'suspicious'
	else if (score >= 1) status = 'clean'
	else status = 'unknown'
	return {
		status,
		score,
		details: {
			confidence: score,
			reports: Number(d.totalReports ?? 0),
			countryCode: d.countryCode || null,
			isp: d.isp || null,
			domain: d.domain || null,
			lastReportedAt: d.lastReportedAt || null,
		}
	}
} 