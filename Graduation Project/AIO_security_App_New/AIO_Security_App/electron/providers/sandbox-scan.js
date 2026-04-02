import { vtFileLookup } from './virustotal.js'
import { metadefenderLookup } from './metadefender.js'
import { urlscanLookup } from './urlscan.js'
import { calculateFileHash } from '../utils/crypto.js'
import fs from 'node:fs/promises'
import path from 'node:path'

async function getFileInfo(filePath, fileName) {
	const stats = await fs.stat(filePath)
	const hashes = await calculateFileHash(filePath)
	
	return {
		name: fileName || path.basename(filePath),
		size: stats.size,
		...hashes
	}
}

function aggregateResults(providerResults) {
	const results = Object.values(providerResults).filter(r => r && r.status !== 'error')
	
	if (results.length === 0) {
		return { status: 'unknown', score: 0, verdict: 'No analysis completed' }
	}
	
	// Prioritize status: malicious > suspicious > clean > unknown
	let finalStatus = 'unknown'
	if (results.some(r => r.status === 'malicious')) {
		finalStatus = 'malicious'
	} else if (results.some(r => r.status === 'suspicious')) {
		finalStatus = 'suspicious'
	} else if (results.some(r => r.status === 'clean')) {
		finalStatus = 'clean'
	}
	
	// Average the scores
	const scores = results.map(r => r.score).filter(s => typeof s === 'number')
	const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0
	
	// Generate verdict summary
	const maliciousCount = results.filter(r => r.status === 'malicious').length
	const suspiciousCount = results.filter(r => r.status === 'suspicious').length
	const cleanCount = results.filter(r => r.status === 'clean').length
	
	let verdict = `${results.length} provider${results.length !== 1 ? 's' : ''} analyzed`
	if (maliciousCount > 0) {
		verdict += ` - ${maliciousCount} flagged as malicious`
	}
	if (suspiciousCount > 0) {
		verdict += ` - ${suspiciousCount} flagged as suspicious`
	}
	if (cleanCount > 0) {
		verdict += ` - ${cleanCount} marked as clean`
	}
	
	return { status: finalStatus, score: avgScore, verdict }
}

export async function scanSandbox({ type, input, providers, settings, jobId }, apiKeys, controllers, onProgress) {
	const enabled = Object.entries(providers).filter(([, v]) => !!v)
	const perProvider = {}
	const providerPromises = []
	
	// Initialize result structure
	let sandboxResult = {
		input: typeof input === 'string' ? input : input.name,
		type,
		status: 'unknown',
		score: 0,
		providers: {},
		verdict: 'Analysis starting...'
	}
	
	if (type === 'file') {
		const filePath = typeof input === 'string' ? input : input.path
		const fileName = typeof input === 'string' ? path.basename(input) : input.name
		
		try {
			sandboxResult.fileInfo = await getFileInfo(filePath, fileName)
		} catch (error) {
			throw new Error(`Failed to read file: ${error.message}`)
		}
		
		// File analysis providers
		for (const [providerKey, enabled] of Object.entries(providers)) {
			if (!enabled) continue
			
			const controller = new AbortController()
			controllers.push(controller)
			
			if (providerKey === 'virustotal') {
				if (!apiKeys.virustotal) {
					perProvider.virustotal = { 
						provider: 'virustotal', 
						status: 'error', 
						score: 0, 
						error: 'VirusTotal API key required' 
					}
					if (onProgress) onProgress({ jobId, provider: 'virustotal', result: perProvider.virustotal })
				} else {
					const allowUpload = settings.allowThirdPartyUploads && !settings.preferReputationFirst
					providerPromises.push(
						vtFileLookup(filePath, apiKeys.virustotal, controller.signal, 
							(progressData) => {
								if (onProgress) onProgress({ jobId, stage: progressData, provider: 'virustotal' })
							}, 
							allowUpload
						)
						.then(r => {
							perProvider.virustotal = { provider: 'virustotal', ...r }
							if (onProgress) onProgress({ jobId, provider: 'virustotal', result: perProvider.virustotal })
						})
						.catch(e => {
							perProvider.virustotal = { 
								provider: 'virustotal', 
								status: 'error', 
								score: 0, 
								error: String(e?.message || e) 
							}
							if (onProgress) onProgress({ jobId, provider: 'virustotal', result: perProvider.virustotal })
						})
					)
				}
			}
			

			if (providerKey === 'metadefender') {
				if (!apiKeys.metadefender) {
					perProvider.metadefender = { 
						provider: 'metadefender', 
						status: 'error', 
						score: 0, 
						error: 'OPSWAT MetaDefender API key required' 
					}
					if (onProgress) onProgress({ jobId, provider: 'metadefender', result: perProvider.metadefender })
				} else if (!settings.allowThirdPartyUploads) {
					perProvider.metadefender = { 
						provider: 'metadefender', 
						status: 'error', 
						score: 0, 
						error: 'Third-party uploads not allowed in settings' 
					}
					if (onProgress) onProgress({ jobId, provider: 'metadefender', result: perProvider.metadefender })
				} else {
					providerPromises.push(
						metadefenderLookup(filePath, apiKeys.metadefender, controller.signal,
							(progressData) => {
								if (onProgress) onProgress({ jobId, stage: progressData, provider: 'metadefender' })
							}
						)
						.then(r => {
							perProvider.metadefender = { provider: 'metadefender', ...r }
							if (onProgress) onProgress({ jobId, provider: 'metadefender', result: perProvider.metadefender })
						})
						.catch(e => {
							perProvider.metadefender = { 
								provider: 'metadefender', 
								status: 'error', 
								score: 0, 
								error: String(e?.message || e) 
							}
							if (onProgress) onProgress({ jobId, provider: 'metadefender', result: perProvider.metadefender })
						})
					)
				}
			}
		}
	} else if (type === 'url') {
		const url = typeof input === 'string' ? input : input.path
		
		// URL analysis providers
		if (providers.urlscan) {
			const controller = new AbortController()
			controllers.push(controller)
			
			providerPromises.push(
				urlscanLookup(url, apiKeys.urlscan, controller.signal,
					(progressData) => {
						if (onProgress) onProgress({ jobId, stage: progressData, provider: 'urlscan' })
					}
				)
				.then(r => {
					perProvider.urlscan = { provider: 'urlscan', ...r }
					if (onProgress) onProgress({ jobId, provider: 'urlscan', result: perProvider.urlscan })
				})
				.catch(e => {
					perProvider.urlscan = { 
						provider: 'urlscan', 
						status: 'error', 
						score: 0, 
						error: String(e?.message || e) 
					}
					if (onProgress) onProgress({ jobId, provider: 'urlscan', result: perProvider.urlscan })
				})
			)
		}
	}
	
	// Wait for all providers to complete
	await Promise.all(providerPromises)
	
	// Aggregate results
	const aggregated = aggregateResults(perProvider)
	
	return {
		...sandboxResult,
		status: aggregated.status,
		score: aggregated.score,
		verdict: aggregated.verdict,
		providers: perProvider
	}
} 