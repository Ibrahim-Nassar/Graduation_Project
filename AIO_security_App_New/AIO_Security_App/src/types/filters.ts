/**
 * Filter types and interfaces for IOC results
 */

export type FilterStatus = 'malicious' | 'suspicious' | 'clean' | 'unknown'
export type FilterIocType = 'ip' | 'domain' | 'url' | 'hash'
export type FilterProvider = 'virustotal' | 'abuseipdb' | 'otx' | 'threatfox'

export interface IocFilters {
	// Basic filters
	statuses: FilterStatus[]
	types: FilterIocType[]
	
	// Score range filter
	scoreRange: {
		min: number
		max: number
	}
	
	// Provider-specific filters
	providers: {
		// VirusTotal: minimum detections
		virustotal?: {
			enabled: boolean
			minDetections?: number
			minEngines?: number
		}
		// AbuseIPDB: confidence and reports
		abuseipdb?: {
			enabled: boolean
			minConfidence?: number
			minReports?: number
		}
		// OTX: pulses
		otx?: {
			enabled: boolean
			minPulses?: number
		}
		// ThreatFox: hits
		threatfox?: {
			enabled: boolean
			minHits?: number
		}
	}
	
	// Text search
	searchTerm: string
}

export const DEFAULT_FILTERS: IocFilters = {
	statuses: [],
	types: [],
	scoreRange: {
		min: 0,
		max: 100
	},
	providers: {},
	searchTerm: ''
}

export interface FilterPreset {
	id: string
	name: string
	description: string
	filters: Partial<IocFilters>
}

export const FILTER_PRESETS: FilterPreset[] = [
	{
		id: 'high-threat',
		name: 'High Threat',
		description: 'Malicious IOCs with high scores',
		filters: {
			statuses: ['malicious'],
			scoreRange: { min: 75, max: 100 }
		}
	},
	{
		id: 'suspicious-only',
		name: 'Suspicious',
		description: 'Potentially suspicious IOCs',
		filters: {
			statuses: ['suspicious']
		}
	},
	{
		id: 'clean-only',
		name: 'Clean',
		description: 'Clean IOCs only',
		filters: {
			statuses: ['clean']
		}
	},
	{
		id: 'ips-malicious',
		name: 'Malicious IPs',
		description: 'Only malicious IP addresses',
		filters: {
			statuses: ['malicious'],
			types: ['ip']
		}
	},
	{
		id: 'vt-detected',
		name: 'VT Detected',
		description: 'Detected by VirusTotal (3+ engines)',
		filters: {
			providers: {
				virustotal: {
					enabled: true,
					minDetections: 3
				}
			}
		}
	},
	{
		id: 'high-abuse',
		name: 'High Abuse Score',
		description: 'AbuseIPDB confidence > 75%',
		filters: {
			providers: {
				abuseipdb: {
					enabled: true,
					minConfidence: 75
				}
			}
		}
	}
]



