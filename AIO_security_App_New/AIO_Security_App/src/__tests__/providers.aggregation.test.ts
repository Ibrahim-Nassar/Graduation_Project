/* @vitest-environment node */
import { describe, it, expect, vi } from 'vitest'
// @ts-ignore JS module without types
import * as scanMod from '../../electron/providers/scan.js'

vi.mock('../../electron/providers/virustotal.js', () => ({ vtLookup: vi.fn(async () => ({ status:'malicious', score:80 })) }))
vi.mock('../../electron/providers/abuseipdb.js', () => ({ abuseipdbLookup: vi.fn(async () => ({ status:'suspicious', score:30 })) }))
vi.mock('../../electron/providers/otx.js', () => ({ otxLookup: vi.fn(async () => ({ status:'unknown', score:0 })) }))
vi.mock('../../electron/providers/threatfox.js', () => ({ threatfoxLookup: vi.fn(async () => ({ status:'unknown', score:0 })) }))

describe('scanWithProviders aggregation', () => {
	it('prioritizes malicious and averages score', async () => {
		const res = await (scanMod as any).scanWithProviders(['8.8.8.8'], { virustotal:true, abuseipdb:true, otx:false, threatfox:false }, { virustotal:'k', abuseipdb:'k' }, [], () => {})
		expect(res[0].status).toBe('malicious')
		expect(res[0].score).toBeGreaterThan(50)
	})
}) 