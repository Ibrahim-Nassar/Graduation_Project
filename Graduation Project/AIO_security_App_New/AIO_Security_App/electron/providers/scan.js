import { vtLookup } from './virustotal.js'
import { abuseipdbLookup } from './abuseipdb.js'
import { otxLookup } from './otx.js'
import { threatfoxLookup } from './threatfox.js'
import { detectIocType, IOC_TYPE } from '../utils/ioc-detection.js'

function aggregateStatus(scores){
	if (!scores.length) return { status: 'unknown', score: 0 }
	const score = Math.round(scores.reduce((a,b)=>a+b,0) / scores.length)
	let status = 'unknown'
	if (score >= 75) status = 'malicious'
	else if (score >= 35) status = 'suspicious'
	else if (score > 0) status = 'clean'
	else status = 'unknown'
	return { status, score }
}

/**
 * Wraps a promise with a timeout
 * @param {Promise} promise - Promise to wrap
 * @param {number} timeoutMs - Timeout in milliseconds
 * @param {string} name - Name for error message
 * @returns {Promise} Promise that rejects if timeout is exceeded
 */
function promiseWithTimeout(promise, timeoutMs, name) {
	return Promise.race([
		promise,
		new Promise((_, reject) => 
			setTimeout(() => reject(new Error(`${name} timed out after ${timeoutMs}ms`)), timeoutMs)
		)
	])
}

export async function scanWithProviders(iocs, providers, apiKeys, controllers, onProgress){
	const enabled = Object.fromEntries(Object.entries(providers || {}).filter(([,v])=>!!v))
	const results = []
	for (let iocIndex = 0; iocIndex < iocs.length; iocIndex++){
		const raw = iocs[iocIndex]
		const type = detectIocType(raw)
		
		// Debug logging
		console.log(`Processing IOC ${iocIndex + 1}/${iocs.length}: "${raw}" → Type: "${type}"`)
		
		if (type === IOC_TYPE.UNKNOWN){
			results.push({ ioc: raw, type, status: 'invalid', score: 0, providers: {}, errors: ['Invalid IOC'] })
			continue
		}
		const perProvider = {}
		const providerPromises = []
		const scores = []

		if (enabled.virustotal){
			if (!apiKeys.virustotal){
				perProvider.virustotal = { provider: 'virustotal', status: 'error', score: 0, error: 'Missing VirusTotal API key' }
				if (onProgress) onProgress(iocIndex, 'virustotal', perProvider.virustotal)
			} else {
				const controller = new AbortController(); controllers.push(controller)
				providerPromises.push(
					promiseWithTimeout(
						vtLookup(raw, type, apiKeys.virustotal, controller.signal),
						45000, // 45 second max per IOC for VT (includes retries)
						'VirusTotal'
					)
						.then(r => { 
							perProvider.virustotal = { provider: 'virustotal', ...r }
							if (r && typeof r.score === 'number') scores.push(r.score)
							if (onProgress) onProgress(iocIndex, 'virustotal', perProvider.virustotal)
						})
						.catch(e => { 
							perProvider.virustotal = { provider: 'virustotal', status: 'error', score: 0, error: String(e?.message || e) }
							if (onProgress) onProgress(iocIndex, 'virustotal', perProvider.virustotal)
						})
				)
			}
		}
		if (enabled.abuseipdb && type === IOC_TYPE.IP){
			console.log(`  ✓ AbuseIPDB: Checking IP "${raw}"`)
			if (!apiKeys.abuseipdb){
				perProvider.abuseipdb = { provider: 'abuseipdb', status: 'error', score: 0, error: 'Missing AbuseIPDB API key' }
				if (onProgress) onProgress(iocIndex, 'abuseipdb', perProvider.abuseipdb)
			} else {
				const controller = new AbortController(); controllers.push(controller)
				providerPromises.push(
					promiseWithTimeout(
						abuseipdbLookup(raw, apiKeys.abuseipdb, controller.signal),
						30000, // 30 second max per IOC for AbuseIPDB
						'AbuseIPDB'
					)
						.then(r => { 
							perProvider.abuseipdb = { provider: 'abuseipdb', ...r }
							if (r && typeof r.score === 'number') scores.push(r.score)
							if (onProgress) onProgress(iocIndex, 'abuseipdb', perProvider.abuseipdb)
						})
						.catch(e => { 
							perProvider.abuseipdb = { provider: 'abuseipdb', status: 'error', score: 0, error: String(e?.message || e) }
							if (onProgress) onProgress(iocIndex, 'abuseipdb', perProvider.abuseipdb)
						})
				)
			}
		} else if (enabled.abuseipdb && type !== IOC_TYPE.IP) {
			// Skip AbuseIPDB for non-IP IOCs (but log for debugging)
			console.log(`  ⊗ AbuseIPDB: Skipping non-IP "${raw}" (type: ${type})`)
		}
		if (enabled.otx){
			if (!apiKeys.otx){
				perProvider.otx = { provider: 'otx', status: 'error', score: 0, error: 'Missing OTX API key' }
				if (onProgress) onProgress(iocIndex, 'otx', perProvider.otx)
			} else {
				const controller = new AbortController(); controllers.push(controller)
				providerPromises.push(
					promiseWithTimeout(
						otxLookup(raw, type, apiKeys.otx, controller.signal),
						45000, // 45 second max per IOC for OTX
						'OTX'
					)
						.then(r => { 
							perProvider.otx = { provider: 'otx', ...r }
							if (r && typeof r.score === 'number') scores.push(r.score)
							if (onProgress) onProgress(iocIndex, 'otx', perProvider.otx)
						})
						.catch(e => { 
							perProvider.otx = { provider: 'otx', status: 'error', score: 0, error: String(e?.message || e) }
							if (onProgress) onProgress(iocIndex, 'otx', perProvider.otx)
						})
				)
			}
		}
		if (enabled.threatfox){
			if (!apiKeys.threatfox){
				perProvider.threatfox = { provider: 'threatfox', status: 'error', score: 0, error: 'ThreatFox API key required. Get one free at auth.abuse.ch' }
				if (onProgress) onProgress(iocIndex, 'threatfox', perProvider.threatfox)
			} else {
				const controller = new AbortController(); controllers.push(controller)
				providerPromises.push(
					promiseWithTimeout(
						threatfoxLookup(raw, type, apiKeys.threatfox, controller.signal),
						45000, // 45 second max per IOC for ThreatFox
						'ThreatFox'
					)
						.then(r => { 
							perProvider.threatfox = { provider: 'threatfox', ...r }
							if (r && typeof r.score === 'number') scores.push(r.score)
							if (onProgress) onProgress(iocIndex, 'threatfox', perProvider.threatfox)
						})
						.catch(e => { 
							perProvider.threatfox = { provider: 'threatfox', status: 'error', score: 0, error: String(e?.message || e) }
							if (onProgress) onProgress(iocIndex, 'threatfox', perProvider.threatfox)
						})
				)
			}
		}

		try {
			await Promise.all(providerPromises)
		} catch (error) {
			// Log the error but continue - individual provider errors are already handled
			console.error(`Error in Promise.all for IOC ${iocIndex} (${raw}):`, error.message)
		}
		// Final aggregation: prioritize any malicious > suspicious > clean
		const providerArr = Object.values(perProvider)
		let finalStatus = 'unknown'
		if (providerArr.some(p => p?.status === 'malicious')) finalStatus = 'malicious'
		else if (providerArr.some(p => p?.status === 'suspicious')) finalStatus = 'suspicious'
		else if (providerArr.some(p => p?.status === 'clean')) finalStatus = 'clean'
		const avgScore = scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : 0
		results.push({ ioc: raw, type, status: finalStatus, score: avgScore, providers: perProvider })
	}
	return results
} 