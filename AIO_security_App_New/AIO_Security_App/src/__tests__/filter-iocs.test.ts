import { describe, it, expect } from 'vitest'
import { filterIocResults } from '../utils/filter-iocs'
import { DEFAULT_FILTERS } from '../types/filters'
import type { IocResult } from '../types'

const createMockResult = (overrides: Partial<IocResult>): IocResult => ({
	ioc: '8.8.8.8',
	type: 'ip',
	status: 'clean',
	score: 10,
	providers: {},
	...overrides
})

describe('filterIocResults', () => {
	it('returns all results with default filters', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: '8.8.8.8', status: 'clean' }),
			createMockResult({ ioc: '1.1.1.1', status: 'malicious' }),
		]

		const filtered = filterIocResults(results, DEFAULT_FILTERS)
		expect(filtered).toHaveLength(2)
	})

	it('filters by status', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: '1', status: 'clean' }),
			createMockResult({ ioc: '2', status: 'malicious' }),
			createMockResult({ ioc: '3', status: 'suspicious' }),
			createMockResult({ ioc: '4', status: 'unknown' }),
		]

		const filters = {
			...DEFAULT_FILTERS,
			status: { malicious: true, suspicious: false, clean: false, unknown: false }
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered).toHaveLength(1)
		expect(filtered[0].status).toBe('malicious')
	})

	it('filters by type', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: '8.8.8.8', type: 'ip' }),
			createMockResult({ ioc: 'example.com', type: 'domain' }),
			createMockResult({ ioc: 'http://test.com', type: 'url' }),
			createMockResult({ ioc: 'abc123', type: 'hash' }),
		]

		const filters = {
			...DEFAULT_FILTERS,
			types: { ip: true, domain: false, url: false, hash: false }
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered).toHaveLength(1)
		expect(filtered[0].type).toBe('ip')
	})

	it('filters by minimum score', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: '1', score: 10 }),
			createMockResult({ ioc: '2', score: 50 }),
			createMockResult({ ioc: '3', score: 75 }),
			createMockResult({ ioc: '4', score: 90 }),
		]

		const filters = {
			...DEFAULT_FILTERS,
			minScore: 60
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered).toHaveLength(2)
		expect(filtered.every(r => r.score >= 60)).toBe(true)
	})

	it('combines multiple filters', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: '1', type: 'ip', status: 'malicious', score: 80 }),
			createMockResult({ ioc: '2', type: 'ip', status: 'clean', score: 10 }),
			createMockResult({ ioc: '3', type: 'domain', status: 'malicious', score: 90 }),
			createMockResult({ ioc: '4', type: 'ip', status: 'malicious', score: 50 }),
		]

		const filters = {
			status: { malicious: true, suspicious: false, clean: false, unknown: false },
			types: { ip: true, domain: false, url: false, hash: false },
			minScore: 60
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered).toHaveLength(1)
		expect(filtered[0].ioc).toBe('1')
	})

	it('returns empty array when no results match', () => {
		const results: IocResult[] = [
			createMockResult({ status: 'clean', score: 10 }),
		]

		const filters = {
			...DEFAULT_FILTERS,
			status: { malicious: true, suspicious: false, clean: false, unknown: false },
			minScore: 80
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered).toHaveLength(0)
	})

	it('handles empty results array', () => {
		const filtered = filterIocResults([], DEFAULT_FILTERS)
		expect(filtered).toHaveLength(0)
	})

	it('preserves result order', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: 'z', status: 'malicious' }),
			createMockResult({ ioc: 'a', status: 'malicious' }),
			createMockResult({ ioc: 'm', status: 'malicious' }),
		]

		const filters = {
			...DEFAULT_FILTERS,
			status: { malicious: true, suspicious: false, clean: false, unknown: false }
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered.map(r => r.ioc)).toEqual(['z', 'a', 'm'])
	})

	it('includes results at exact minimum score threshold', () => {
		const results: IocResult[] = [
			createMockResult({ ioc: '1', score: 49 }),
			createMockResult({ ioc: '2', score: 50 }),
			createMockResult({ ioc: '3', score: 51 }),
		]

		const filters = {
			...DEFAULT_FILTERS,
			minScore: 50
		}

		const filtered = filterIocResults(results, filters)
		expect(filtered).toHaveLength(2)
		expect(filtered.some(r => r.score === 50)).toBe(true)
	})
})

