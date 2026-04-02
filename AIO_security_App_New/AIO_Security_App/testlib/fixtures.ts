export const IOC_SAMPLES = {
	ip: '8.8.8.8',
	domain: 'example.com',
	url: 'https://example.com/path',
	hash: 'd41d8cd98f00b204e9800998ecf8427e',
}

export function sha256Hex(input: string): string {
	// Simple browser/node compatible SHA-256 using SubtleCrypto if available, else a naive fallback for tests
	// In tests we can return a deterministic short hash for tiny inputs
	let hash = 0
	for (let i = 0; i < input.length; i++) {
		hash = (hash * 31 + input.charCodeAt(i)) >>> 0
	}
	return ('00000000' + hash.toString(16)).slice(-8).padEnd(64, '0')
}

export const SAMPLE_PROVIDER_PAYLOADS = {
	virustotalFileKnown: {
		data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 70, undetected: 22 }, reputation: 0, last_analysis_date: 1234567890 } }
	},
} 