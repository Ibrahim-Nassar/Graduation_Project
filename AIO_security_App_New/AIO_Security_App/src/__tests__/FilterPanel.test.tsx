import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import FilterPanel from '../components/FilterPanel'
import { DEFAULT_FILTERS } from '../types/filters'

describe('FilterPanel Component', () => {
	it('renders with default filters', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={10}
				totalCount={10}
			/>
		)

		expect(screen.getByText('Filters')).toBeInTheDocument()
		expect(screen.getByText(/Showing 10 of 10 IOCs/)).toBeInTheDocument()
	})

	it('shows filtered count correctly', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={5}
				totalCount={10}
			/>
		)

		expect(screen.getByText(/Showing 5 of 10 IOCs/)).toBeInTheDocument()
	})

	it('shows scanning status when scan is in progress', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={10}
				totalCount={10}
				isScanning={true}
				completedCount={5}
			/>
		)

		expect(screen.getByText(/Showing 10 of 10 IOCs/)).toBeInTheDocument()
		expect(screen.getByText(/5 fully analyzed/)).toBeInTheDocument()
	})

	it('calls onChange when status filter is toggled', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={10}
				totalCount={10}
			/>
		)

		const maliciousCheckbox = screen.getByLabelText(/Malicious/i)
		fireEvent.click(maliciousCheckbox)

		expect(onChange).toHaveBeenCalledWith(
			expect.objectContaining({
				status: expect.objectContaining({
					malicious: false
				})
			})
		)
	})

	it('calls onChange when type filter is toggled', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={10}
				totalCount={10}
			/>
		)

		const ipCheckbox = screen.getByLabelText(/IP/i)
		fireEvent.click(ipCheckbox)

		expect(onChange).toHaveBeenCalledWith(
			expect.objectContaining({
				types: expect.objectContaining({
					ip: false
				})
			})
		)
	})

	it('calls onChange when min score is changed', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={10}
				totalCount={10}
			/>
		)

		const scoreInput = screen.getByLabelText(/Minimum Score/i)
		fireEvent.change(scoreInput, { target: { value: '50' } })

		expect(onChange).toHaveBeenCalledWith(
			expect.objectContaining({
				minScore: 50
			})
		)
	})

	it('resets filters when Reset button is clicked', () => {
		const onChange = vi.fn()
		const customFilters = {
			status: { malicious: false, suspicious: true, clean: true, unknown: true },
			types: { ip: true, domain: true, url: true, hash: true },
			minScore: 50
		}

		render(
			<FilterPanel
				filters={customFilters}
				onChange={onChange}
				resultCount={5}
				totalCount={10}
			/>
		)

		const resetButton = screen.getByText('Reset Filters')
		fireEvent.click(resetButton)

		expect(onChange).toHaveBeenCalledWith(DEFAULT_FILTERS)
	})

	it('displays warning when filters reduce results', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={2}
				totalCount={10}
			/>
		)

		expect(screen.getByText(/8 results hidden by filters/i)).toBeInTheDocument()
	})

	it('does not show warning when all results are visible', () => {
		const onChange = vi.fn()
		render(
			<FilterPanel
				filters={DEFAULT_FILTERS}
				onChange={onChange}
				resultCount={10}
				totalCount={10}
			/>
		)

		expect(screen.queryByText(/hidden by filters/i)).not.toBeInTheDocument()
	})
})

