import { describe, it, expect } from 'vitest'
import { formatFileSize, toCountryName, toFlagEmoji } from '../utils/formatting'

describe('Formatting Utilities', () => {
	describe('formatFileSize', () => {
		it('formats bytes', () => {
			expect(formatFileSize(500)).toBe('500 B')
			expect(formatFileSize(1023)).toBe('1023 B')
		})

		it('formats kilobytes', () => {
			expect(formatFileSize(1024)).toBe('1.00 KB')
			expect(formatFileSize(1536)).toBe('1.50 KB')
			expect(formatFileSize(10240)).toBe('10.00 KB')
		})

		it('formats megabytes', () => {
			expect(formatFileSize(1048576)).toBe('1.00 MB')
			expect(formatFileSize(5242880)).toBe('5.00 MB')
			expect(formatFileSize(10485760)).toBe('10.00 MB')
		})

		it('formats gigabytes', () => {
			expect(formatFileSize(1073741824)).toBe('1.00 GB')
			expect(formatFileSize(5368709120)).toBe('5.00 GB')
		})

		it('handles zero', () => {
			expect(formatFileSize(0)).toBe('0 B')
		})

		it('handles negative numbers', () => {
			expect(formatFileSize(-1024)).toBe('-1.00 KB')
		})

		it('handles decimal values', () => {
			const result = formatFileSize(1536.7)
			expect(result).toBe('1.50 KB')
		})

		it('handles very large numbers', () => {
			const result = formatFileSize(1099511627776) // 1 TB
			expect(result).toContain('GB') // Will show in GB
		})
	})

	describe('toCountryName', () => {
		it('converts common country codes', () => {
			expect(toCountryName('US')).toBe('United States')
			expect(toCountryName('GB')).toBe('United Kingdom')
			expect(toCountryName('CA')).toBe('Canada')
			expect(toCountryName('DE')).toBe('Germany')
			expect(toCountryName('FR')).toBe('France')
		})

		it('handles lowercase codes', () => {
			expect(toCountryName('us')).toBe('United States')
			expect(toCountryName('gb')).toBe('United Kingdom')
		})

		it('returns code for unknown countries', () => {
			expect(toCountryName('XX')).toBe('XX')
			expect(toCountryName('ZZ')).toBe('ZZ')
		})

		it('handles empty string', () => {
			expect(toCountryName('')).toBe('')
		})
	})

	describe('toFlagEmoji', () => {
		it('converts country codes to flag emojis', () => {
			expect(toFlagEmoji('US')).toBeTruthy()
			expect(toFlagEmoji('GB')).toBeTruthy()
			expect(toFlagEmoji('CA')).toBeTruthy()
		})

		it('handles lowercase codes', () => {
			expect(toFlagEmoji('us')).toBeTruthy()
			expect(toFlagEmoji('fr')).toBeTruthy()
		})

		it('handles invalid codes', () => {
			expect(toFlagEmoji('')).toBe('')
			expect(toFlagEmoji('X')).toBeTruthy() // Still produces unicode
		})

		it('produces different emojis for different countries', () => {
			const us = toFlagEmoji('US')
			const ca = toFlagEmoji('CA')
			expect(us).not.toBe(ca)
		})
	})
})

