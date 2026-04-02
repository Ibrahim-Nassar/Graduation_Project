/**
 * IOC filtering logic
 */

import type { IocResult } from '../types'
import type { IocFilters } from '../types/filters'

/**
 * Applies filters to an array of IOC results
 * @param results - IOC results to filter
 * @param filters - Active filters
 * @returns Filtered IOC results
 */
export function filterIocResults(results: IocResult[], filters: IocFilters): IocResult[] {
	return results.filter(result => {
		// Status filter
		if (filters.statuses.length > 0) {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			if (!filters.statuses.includes(result.status as any)) {
				return false
			}
		}
		
		// Type filter
		if (filters.types.length > 0) {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			if (!filters.types.includes(result.type as any)) {
				return false
			}
		}
		
		// Score range filter
		if (result.score < filters.scoreRange.min || result.score > filters.scoreRange.max) {
			return false
		}
		
		// Search term filter
		if (filters.searchTerm) {
			const searchLower = filters.searchTerm.toLowerCase()
			if (!result.ioc.toLowerCase().includes(searchLower)) {
				return false
			}
		}
		
		// Provider-specific filters
		
		// VirusTotal filter
		if (filters.providers.virustotal?.enabled) {
			const vt = result.providers?.virustotal
			if (!vt) return false
			
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const details = vt.details as any
			if (filters.providers.virustotal.minDetections !== undefined) {
				const detections = details?.maliciousCount ?? 0
				if (detections < filters.providers.virustotal.minDetections) {
					return false
				}
			}
			if (filters.providers.virustotal.minEngines !== undefined) {
				const engines = details?.enginesTotal ?? 0
				if (engines < filters.providers.virustotal.minEngines) {
					return false
				}
			}
		}
		
		// AbuseIPDB filter
		if (filters.providers.abuseipdb?.enabled) {
			const abuse = result.providers?.abuseipdb
			if (!abuse) return false
			
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const details = abuse.details as any
			if (filters.providers.abuseipdb.minConfidence !== undefined) {
				const confidence = details?.confidence ?? 0
				if (confidence < filters.providers.abuseipdb.minConfidence) {
					return false
				}
			}
			if (filters.providers.abuseipdb.minReports !== undefined) {
				const reports = details?.reports ?? 0
				if (reports < filters.providers.abuseipdb.minReports) {
					return false
				}
			}
		}
		
		// OTX filter
		if (filters.providers.otx?.enabled) {
			const otx = result.providers?.otx
			if (!otx) return false
			
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const details = otx.details as any
			if (filters.providers.otx.minPulses !== undefined) {
				const pulses = details?.pulses ?? 0
				if (pulses < filters.providers.otx.minPulses) {
					return false
				}
			}
		}
		
		// ThreatFox filter
		if (filters.providers.threatfox?.enabled) {
			const tf = result.providers?.threatfox
			if (!tf) return false
			
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const details = tf.details as any
			if (filters.providers.threatfox.minHits !== undefined) {
				const hits = details?.count ?? 0
				if (hits < filters.providers.threatfox.minHits) {
					return false
				}
			}
		}
		
		return true
	})
}

/**
 * Counts how many active filters are applied
 * @param filters - Current filters
 * @returns Number of active filters
 */
export function countActiveFilters(filters: IocFilters): number {
	let count = 0
	
	if (filters.statuses.length > 0) count++
	if (filters.types.length > 0) count++
	if (filters.scoreRange.min > 0 || filters.scoreRange.max < 100) count++
	if (filters.searchTerm) count++
	
	if (filters.providers.virustotal?.enabled) count++
	if (filters.providers.abuseipdb?.enabled) count++
	if (filters.providers.otx?.enabled) count++
	if (filters.providers.threatfox?.enabled) count++
	
	return count
}

/**
 * Checks if any filters are active
 * @param filters - Current filters
 * @returns True if any filters are active
 */
export function hasActiveFilters(filters: IocFilters): boolean {
	return countActiveFilters(filters) > 0
}

