import type { IocResult } from '../types'

type UnknownRecord = Record<string, unknown>

function escapeCsv(value: unknown): string {
	if (value === null || value === undefined) return ''
	const str = String(value)
	if (/[",\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"'
	return str
}

function getProviderLabel(p: unknown): string {
	if (!p || typeof p !== 'object') return ''
	const rec = p as UnknownRecord
	const status = typeof rec.status === 'string' ? rec.status : ''
	const error = typeof rec.error === 'string' ? rec.error : ''
	const provider = typeof rec.provider === 'string' ? rec.provider : ''
	const details = (rec.details && typeof rec.details === 'object') ? (rec.details as UnknownRecord) : undefined
	if (status === 'error' && /missing/i.test(error)) return 'n/a'
	let label = status
	let extra = ''
	if (provider === 'virustotal' && details) {
		const malicious = Number(details.maliciousCount ?? 0)
		const total = Number(details.enginesTotal ?? 0)
		if (total > 0) extra = ` (${malicious}/${total})`
	} else if (provider === 'abuseipdb' && details) {
		const confidence = Number(details.confidence ?? 0)
		const reports = Number(details.reports ?? 0)
		if (confidence > 0 || reports > 0) extra = ` (${confidence}% conf, ${reports} reports)`
	} else if (provider === 'otx' && details) {
		const pulses = Number(details.pulses ?? 0)
		if (pulses > 0) extra = ` (${pulses} pulses)`
	} else if (provider === 'threatfox' && details) {
		const count = Number(details.count ?? 0)
		if (count > 0) extra = ` (${count} hits)`
	}
	return String(label + extra)
}

export function toCsv(results: IocResult[]): string {
	const headers = ['IOC','Type','VirusTotal','AbuseIPDB','OTX','ThreatFox']
	const rows = [headers.join(',')]
	for (const r of results){
		const vt = getProviderLabel(r.providers?.virustotal as unknown)
		const ab = getProviderLabel(r.providers?.abuseipdb as unknown)
		const ot = getProviderLabel(r.providers?.otx as unknown)
		const tf = getProviderLabel(r.providers?.threatfox as unknown)
		rows.push([
			escapeCsv(r.ioc),
			escapeCsv(r.type),
			escapeCsv(vt),
			escapeCsv(ab),
			escapeCsv(ot),
			escapeCsv(tf),
		].join(','))
	}
	return rows.join('\n')
} 