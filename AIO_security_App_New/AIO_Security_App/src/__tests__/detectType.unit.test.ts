import { describe, it, expect } from 'vitest'
import { extractIOCsFromText } from '../utils/ioc'

function detectIocType(value: string){
	const v = String(value || '').trim()
	if (!v) return 'unknown'
	if (/^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(v)) return 'ip'
	if (/^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i.test(v)) return 'ip'
	try { const u = new URL(v); if (u.protocol === 'http:' || u.protocol === 'https:') return 'url' } catch {}
	if (/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$/.test(v)) return 'domain'
	if (/^[a-f0-9]{32}$/i.test(v) || /^[a-f0-9]{40}$/i.test(v) || /^[a-f0-9]{64}$/i.test(v)) return 'hash'
	return 'unknown'
}

describe('detectIocType', () => {
	it('detects IPv4', () => {
		expect(detectIocType('8.8.8.8')).toBe('ip')
	})
	it('detects URL', () => {
		expect(detectIocType('https://example.com/a')).toBe('url')
	})
	it('detects domain', () => {
		expect(detectIocType('mal.example.com')).toBe('domain')
	})
	it('detects hash', () => {
		expect(detectIocType('d41d8cd98f00b204e9800998ecf8427e')).toBe('hash')
	})
})

describe('extractIOCsFromText', () => {
	it('extracts from CSV with header', () => {
		const text = 'Type,Value\nIP,8.8.8.8\nIP,1.1.1.1'
		const out = extractIOCsFromText(text)
		expect(out).toContain('8.8.8.8')
		expect(out).toContain('1.1.1.1')
	})
	it('extracts from mixed lines with labels', () => {
		const text = 'ioc: example.com, suspicious site; url: https://bad.test/a'
		const out = extractIOCsFromText(text)
		expect(out.some(x => x.includes('example.com'))).toBe(true)
		expect(out.some(x => x.startsWith('http'))).toBe(true)
	})
}) 