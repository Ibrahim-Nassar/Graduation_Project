export const NETWORK = {
	defaultTimeoutMs: 20000,
	uploadTimeoutMs: 120000,
	pollIntervalMs: 5000,
	maxRetries: 4,
	initialBackoffMs: 400,
	maxBackoffMs: 8000,
}

export const ENDPOINTS = {
	virustotal: 'https://www.virustotal.com/api/v3',
	abuseipdb: 'https://api.abuseipdb.com/api/v2',
	otx: 'https://otx.alienvault.com',
	threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
	metadefender: 'https://api.metadefender.com/v4',
	urlscan: 'https://urlscan.io/api/v1',
}

export const SANDBOX = {
	maxUploadBytes: 50 * 1024 * 1024, // 50MB
}

export const RATE_LIMITS: Array<{ key: 'virustotal'|'abuseipdb'|'otx'|'threatfox'|'metadefender'|'urlscan'; name: string; summary: string; docsUrl: string }> = [
	{ key: 'virustotal', name: 'VirusTotal', summary: 'Free tier ~4 requests/min (v3); uploads are queued.', docsUrl: 'https://developers.virustotal.com/reference/overview' },
	{ key: 'abuseipdb', name: 'AbuseIPDB', summary: 'Free tier typically ~1,000 requests/day.', docsUrl: 'https://docs.abuseipdb.com/' },
	{ key: 'otx', name: 'OTX (AlienVault)', summary: 'No official public limits; reasonable usage recommended; 429 if exceeded.', docsUrl: 'https://otx.alienvault.com/api' },
	{ key: 'threatfox', name: 'ThreatFox (abuse.ch)', summary: 'No strict published limits; API key required; be considerate.', docsUrl: 'https://threatfox.abuse.ch/api/' },
	{ key: 'metadefender', name: 'OPSWAT MetaDefender', summary: 'Limits depend on account plan; uploads may be rate-limited.', docsUrl: 'https://onlinehelp.opswat.com/mdcloud/OPSWAT_MetaDefender_Cloud_API.html' },
	{ key: 'urlscan', name: 'urlscan.io', summary: 'Search endpoints have generous limits; higher with API key. Free tier is search-only here.', docsUrl: 'https://urlscan.io/docs/api/' },
] 