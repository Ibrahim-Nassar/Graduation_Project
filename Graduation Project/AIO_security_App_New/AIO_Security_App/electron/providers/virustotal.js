import fs from 'node:fs'
import FormData from 'form-data'
import { createHttpClient, httpRequest } from '../net/http.js'
import { calculateFileHash } from '../utils/crypto.js'

function vtUrlId(url){
	const b64 = Buffer.from(url, 'utf8').toString('base64').replace(/=+$/,'')
	return b64
}

export async function vtLookup(value, type, apiKey, signal){
	if (!apiKey) throw new Error('Missing VirusTotal API key')
	const client = createHttpClient('https://www.virustotal.com/api/v3', { 'x-apikey': apiKey }, 20000)
	let endpoint = ''
	if (type === 'ip') endpoint = `/ip_addresses/${encodeURIComponent(value)}`
	else if (type === 'domain') endpoint = `/domains/${encodeURIComponent(value)}`
	else if (type === 'hash') endpoint = `/files/${encodeURIComponent(value)}`
	else if (type === 'url') endpoint = `/urls/${vtUrlId(String(value))}`
	else throw new Error('Unsupported type for VT')
	const data = await httpRequest(client, { url: endpoint, method: 'GET', signal, __provider: 'virustotal' })
	const attrs = data?.data?.attributes || {}
	const stats = attrs.last_analysis_stats || {}
	const malicious = Number(stats.malicious || 0)
	const suspicious = Number(stats.suspicious || 0)
	const harmless = Number(stats.harmless || 0)
	const undetected = Number(stats.undetected || 0)
	const total = malicious + suspicious + harmless + undetected
	const score = total > 0 ? Math.round((malicious / total) * 100) : 0
	let status = 'unknown'
	if (malicious > 0) status = 'malicious'
	else if (suspicious > 0) status = 'suspicious'
	else if (harmless > 0) status = 'clean'
	else status = 'unknown'
	const ipMeta = type === 'ip' ? {
		country: attrs.country || null,
		asn: attrs.asn || null,
		asnOwner: attrs.as_owner || null,
	} : undefined
	return { status, score, details: { stats, enginesTotal: total, maliciousCount: malicious, meta: ipMeta } }
}

export async function vtFileLookup(filePath, apiKey, signal, onProgress, allowUpload = false) {
	if (!apiKey) throw new Error('Missing VirusTotal API key')
	const startTime = Date.now()
	const client = createHttpClient('https://www.virustotal.com/api/v3', { 'x-apikey': apiKey }, 30000)
	const hashes = await calculateFileHash(filePath)
	const sha256 = hashes.sha256
	try {
		if (onProgress) onProgress({ stage: 'analyzing', provider: 'virustotal', progress: 10 })
		const data = await httpRequest(client, { url: `/files/${sha256}` , method: 'GET', signal, __provider: 'virustotal' })
		const attrs = data?.data?.attributes || {}
		const stats = attrs.last_analysis_stats || {}
		const malicious = Number(stats.malicious || 0)
		const suspicious = Number(stats.suspicious || 0)
		const harmless = Number(stats.harmless || 0)
		const undetected = Number(stats.undetected || 0)
		const total = malicious + suspicious + harmless + undetected
		const score = total > 0 ? Math.round((malicious / total) * 100) : 0
		let status = 'unknown'
		if (malicious >= 3) status = 'malicious'
		else if (malicious > 0 || suspicious > 0) status = 'suspicious'
		else if (harmless > 0) status = 'clean'
		const evidence = [
			`malicious=${malicious}`,
			`suspicious=${suspicious}`,
			`harmless=${harmless}`,
			`undetected=${undetected}`,
			`reputation=${attrs.reputation || 0}`,
			`last_analysis=${attrs.last_analysis_date || 'unknown'}`
		]
		return {
			status,
			score,
			evidence,
			raw_ref: `https://www.virustotal.com/gui/file/${sha256}`,
			latency_ms: Date.now() - startTime,
			cache_hit: true,
			details: { stats, enginesTotal: total, maliciousCount: malicious, hashes }
		}
	} catch (error) {
		if (error?.response?.status === 404 && allowUpload) {
			return await vtFileUpload(filePath, hashes, client, onProgress, startTime, signal)
		}
		throw error
	}
}

async function vtFileUpload(filePath, hashes, client, onProgress, startTime, signal) {
	if (onProgress) onProgress({ stage: 'uploading', provider: 'virustotal', progress: 20 })
	const form = new FormData()
	form.append('file', fs.createReadStream(filePath))
	await httpRequest(client, { url: '/files', method: 'POST', data: form, headers: form.getHeaders(), timeout: 120000, signal, __provider: 'virustotal' })
	if (onProgress) onProgress({ stage: 'analyzing', provider: 'virustotal', progress: 40 })
	let attempts = 0
	const maxAttempts = 30
	while (attempts < maxAttempts) {
		try {
			const data = await httpRequest(client, { url: `/files/${hashes.sha256}`, method: 'GET', signal, __provider: 'virustotal' })
			const attrs = data?.data?.attributes || {}
			const stats = attrs.last_analysis_stats || {}
			const malicious = Number(stats.malicious || 0)
			const suspicious = Number(stats.suspicious || 0)
			const harmless = Number(stats.harmless || 0)
			const undetected = Number(stats.undetected || 0)
			const total = malicious + suspicious + harmless + undetected
			if (attrs.last_analysis_date) {
				const score = total > 0 ? Math.round((malicious / total) * 100) : 0
				let status = 'unknown'
				if (malicious >= 3) status = 'malicious'
				else if (malicious > 0 || suspicious > 0) status = 'suspicious'
				else if (harmless > 0) status = 'clean'
				const evidence = [
					`malicious=${malicious}`,
					`suspicious=${suspicious}`,
					`harmless=${harmless}`,
					`undetected=${undetected}`,
					`reputation=${attrs.reputation || 0}`,
					`last_analysis=${attrs.last_analysis_date || 'unknown'}`
				]
				return {
					status,
					score,
					evidence,
					raw_ref: `https://www.virustotal.com/gui/file/${hashes.sha256}`,
					latency_ms: Date.now() - startTime,
					cache_hit: false,
					details: { stats, enginesTotal: total, maliciousCount: malicious, hashes }
				}
			}
		} catch (pollError) {
			if (pollError?.response?.status === 404) {
				// still processing
			}
		}
		await new Promise(r => setTimeout(r, 10000))
		attempts++
		if (onProgress) {
			const progress = Math.min(95, 40 + (attempts / maxAttempts) * 40)
			onProgress({ stage: 'analyzing', provider: 'virustotal', progress })
		}
	}
	throw new Error('Analysis timeout - file analysis took too long to complete')
} 