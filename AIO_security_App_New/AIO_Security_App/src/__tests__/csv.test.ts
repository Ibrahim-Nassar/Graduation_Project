import { describe, it, expect } from 'vitest'
import { toCsv } from '../utils/csv'
import type { IocResult } from '../types'

describe('toCsv', () => {
	it('builds CSV with headers and rows', () => {
		const results: IocResult[] = [
			{
				ioc: '1.2.3.4',
				type: 'ip',
				status: 'malicious',
				score: 87,
				providers: {
					virustotal: { 
						provider:'virustotal', 
						status:'malicious', 
						score:87,
						details: { maliciousCount: 10, enginesTotal: 95 }
					},
					abuseipdb: { 
						provider:'abuseipdb', 
						status:'suspicious', 
						score:36,
						details: { confidence: 36, reports: 12 }
					},
					otx: { 
						provider:'otx', 
						status:'unknown', 
						score:0,
						details: { pulses: 0 }
					},
					threatfox: { 
						provider:'threatfox', 
						status:'error', 
						score:0 
					}
				}
			}
		]
		const csv = toCsv(results)
		expect(csv.split('\n')[0]).toBe('IOC,Type,VirusTotal,AbuseIPDB,OTX,ThreatFox')
		expect(csv).toContain('1.2.3.4')
		expect(csv).toContain('malicious (10/95)')
		expect(csv).toContain('suspicious (36% conf, 12 reports)')
	})
}) 