import { http, HttpResponse } from 'msw'

export const handlers = [
	// VirusTotal file known
	http.get('https://www.virustotal.com/api/v3/files/:sha256', ({ params }) => {
		const sha256 = params.sha256 as string
		if (sha256 === 'known') {
			return HttpResponse.json({ data: { attributes: { last_analysis_stats: { malicious: 1, suspicious: 0, harmless: 70, undetected: 20 }, reputation: 0, last_analysis_date: 123 } } })
		}
		return new HttpResponse(null, { status: 404 })
	}),
] 