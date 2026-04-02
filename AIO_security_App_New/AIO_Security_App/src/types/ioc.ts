export type IocType = 'ip' | 'domain' | 'url' | 'hash'

export type ParsedIOC =
	| { type: 'ip'; value: string }
	| { type: 'domain'; value: string }
	| { type: 'url'; value: string }
	| { type: 'hash'; value: string }

export function detectIocType(value: string): IocType | 'unknown' {
	const v = String(value || '').trim()
	if (!v) return 'unknown'
	if (/^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(v)) return 'ip'
	if (/^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(v)) return 'ip'
	try { const u = new URL(v); if (u.protocol === 'http:' || u.protocol === 'https:') return 'url' } catch {}
	if (/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$/.test(v)) return 'domain'
	if (/^[a-f0-9]{32}$/i.test(v) || /^[a-f0-9]{40}$/i.test(v) || /^[a-f0-9]{64}$/i.test(v)) return 'hash'
	return 'unknown'
} 