import React, { useState } from 'react'
import type { IocFilters, FilterPreset } from '../types/filters'
import { DEFAULT_FILTERS, FILTER_PRESETS } from '../types/filters'
import { countActiveFilters } from '../utils/filter-iocs'

interface FilterPanelProps {
	filters: IocFilters
	onChange: (filters: IocFilters) => void
	resultCount: number
	totalCount: number
	isScanning?: boolean
	completedCount?: number
}

export default function FilterPanel({ filters, onChange, resultCount, totalCount, isScanning = false, completedCount = 0 }: FilterPanelProps) {
	const [isExpanded, setIsExpanded] = useState(false)
	const [activeTab, setActiveTab] = useState<'basic' | 'providers' | 'presets'>('basic')
	
	const activeFilterCount = countActiveFilters(filters)
	
	const handleReset = () => {
		onChange(DEFAULT_FILTERS)
	}
	
	const handlePreset = (preset: FilterPreset) => {
		onChange({ ...DEFAULT_FILTERS, ...preset.filters })
	}
	
	const toggleStatus = (status: typeof filters.statuses[number]) => {
		const current = filters.statuses
		const newStatuses = current.includes(status)
			? current.filter(s => s !== status)
			: [...current, status]
		onChange({ ...filters, statuses: newStatuses })
	}
	
	const toggleType = (type: typeof filters.types[number]) => {
		const current = filters.types
		const newTypes = current.includes(type)
			? current.filter(t => t !== type)
			: [...current, type]
		onChange({ ...filters, types: newTypes })
	}
	
	return (
		<div className="card panel" style={{ marginBottom: '16px' }}>
			{/* Filter Header */}
			<div 
				className="card-header" 
				style={{ 
					cursor: 'pointer', 
					display: 'flex', 
					justifyContent: 'space-between', 
					alignItems: 'center',
					userSelect: 'none'
				}}
				onClick={() => setIsExpanded(!isExpanded)}
			>
				<h3 className="card-title">
					Filters
					{activeFilterCount > 0 && (
						<span 
							className="badge info" 
							style={{ marginLeft: '8px', fontSize: '12px' }}
						>
							{activeFilterCount} active
						</span>
					)}
				</h3>
				<div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
					<span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
						{isScanning ? (
							<>Showing {resultCount} of {totalCount} IOCs</>
						) : (
							`Showing ${resultCount} of ${totalCount} IOCs`
						)}
					</span>
					<span className="collapsible-icon">{isExpanded ? '−' : '+'}</span>
				</div>
			</div>
			
			{/* Filter Content */}
			{isExpanded && (
				<div style={{ padding: '16px' }}>
					{/* Tabs */}
					<div style={{ 
						display: 'flex', 
						gap: '8px', 
						marginBottom: '16px',
						borderBottom: '1px solid var(--border-primary)',
						paddingBottom: '8px'
					}}>
						<button
							className={`button ${activeTab === 'basic' ? 'primary' : 'ghost'}`}
							onClick={() => setActiveTab('basic')}
							style={{ fontSize: '13px', padding: '6px 12px' }}
						>
							Basic
						</button>
						<button
							className={`button ${activeTab === 'providers' ? 'primary' : 'ghost'}`}
							onClick={() => setActiveTab('providers')}
							style={{ fontSize: '13px', padding: '6px 12px' }}
						>
							Providers
						</button>
						<button
							className={`button ${activeTab === 'presets' ? 'primary' : 'ghost'}`}
							onClick={() => setActiveTab('presets')}
							style={{ fontSize: '13px', padding: '6px 12px' }}
						>
							Presets
						</button>
						<div style={{ flex: 1 }} />
						{activeFilterCount > 0 && (
							<button
								className="button danger"
								onClick={handleReset}
								style={{ fontSize: '13px', padding: '6px 12px' }}
							>
								Reset All
							</button>
						)}
					</div>
					
					{/* Basic Filters Tab */}
					{activeTab === 'basic' && (
						<div style={{ display: 'grid', gap: '16px' }}>
							{/* Status Filter */}
							<div>
								<label className="label">Status</label>
								<div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
									{(['malicious', 'suspicious', 'clean', 'unknown'] as const).map(status => (
										<label key={status} className="provider-checkbox" style={{ margin: 0 }}>
											<input
												type="checkbox"
												checked={filters.statuses.includes(status)}
												onChange={() => toggleStatus(status)}
											/>
											<span className={`badge ${status}`} style={{ textTransform: 'capitalize' }}>
												{status}
											</span>
										</label>
									))}
								</div>
							</div>
							
							{/* Type Filter */}
							<div>
								<label className="label">IOC Type</label>
								<div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
									{(['ip', 'domain', 'url', 'hash'] as const).map(type => (
										<label key={type} className="provider-checkbox" style={{ margin: 0 }}>
											<input
												type="checkbox"
												checked={filters.types.includes(type)}
												onChange={() => toggleType(type)}
											/>
											<span className={`badge ${type}`} style={{ textTransform: 'uppercase' }}>
												{type}
											</span>
										</label>
									))}
								</div>
							</div>
							
							{/* Score Range */}
							<div>
								<label className="label">
									Score Range: {filters.scoreRange.min} - {filters.scoreRange.max}
								</label>
								<div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
									<input
										type="range"
										min="0"
										max="100"
										value={filters.scoreRange.min}
										onChange={(e) => onChange({ 
											...filters, 
											scoreRange: { ...filters.scoreRange, min: Number(e.target.value) }
										})}
										style={{ flex: 1 }}
									/>
									<input
										type="range"
										min="0"
										max="100"
										value={filters.scoreRange.max}
										onChange={(e) => onChange({ 
											...filters, 
											scoreRange: { ...filters.scoreRange, max: Number(e.target.value) }
										})}
										style={{ flex: 1 }}
									/>
								</div>
							</div>
							
							{/* Search */}
							<div>
								<label className="label">Search IOC</label>
								<input
									type="text"
									className="input"
									placeholder="Search by IOC value..."
									value={filters.searchTerm}
									onChange={(e) => onChange({ ...filters, searchTerm: e.target.value })}
								/>
							</div>
						</div>
					)}
					
					{/* Provider Filters Tab */}
					{activeTab === 'providers' && (
						<div style={{ display: 'grid', gap: '16px' }}>
							{/* VirusTotal */}
							<div className="card" style={{ padding: '12px' }}>
								<label className="provider-checkbox" style={{ marginBottom: '8px' }}>
									<input
										type="checkbox"
										checked={filters.providers.virustotal?.enabled || false}
										onChange={(e) => onChange({
											...filters,
											providers: {
												...filters.providers,
												virustotal: {
													...filters.providers.virustotal,
													enabled: e.target.checked
												}
											}
										})}
									/>
									<span style={{ fontWeight: 600 }}>VirusTotal</span>
								</label>
								{filters.providers.virustotal?.enabled && (
									<div style={{ display: 'grid', gap: '8px', marginLeft: '24px' }}>
										<div>
											<label className="label" style={{ fontSize: '12px' }}>Min Detections</label>
											<input
												type="number"
												className="input"
												min="0"
												placeholder="e.g., 3"
												value={filters.providers.virustotal.minDetections ?? ''}
												onChange={(e) => onChange({
													...filters,
													providers: {
														...filters.providers,
														virustotal: {
															...filters.providers.virustotal,
															enabled: true,
															minDetections: e.target.value ? Number(e.target.value) : undefined
														}
													}
												})}
											/>
										</div>
									</div>
								)}
							</div>
							
							{/* AbuseIPDB */}
							<div className="card" style={{ padding: '12px' }}>
								<label className="provider-checkbox" style={{ marginBottom: '8px' }}>
									<input
										type="checkbox"
										checked={filters.providers.abuseipdb?.enabled || false}
										onChange={(e) => onChange({
											...filters,
											providers: {
												...filters.providers,
												abuseipdb: {
													...filters.providers.abuseipdb,
													enabled: e.target.checked
												}
											}
										})}
									/>
									<span style={{ fontWeight: 600 }}>AbuseIPDB</span>
								</label>
								{filters.providers.abuseipdb?.enabled && (
									<div style={{ display: 'grid', gap: '8px', marginLeft: '24px' }}>
										<div>
											<label className="label" style={{ fontSize: '12px' }}>Min Confidence %</label>
											<input
												type="number"
												className="input"
												min="0"
												max="100"
												placeholder="e.g., 75"
												value={filters.providers.abuseipdb.minConfidence ?? ''}
												onChange={(e) => onChange({
													...filters,
													providers: {
														...filters.providers,
														abuseipdb: {
															...filters.providers.abuseipdb,
															enabled: true,
															minConfidence: e.target.value ? Number(e.target.value) : undefined
														}
													}
												})}
											/>
										</div>
										<div>
											<label className="label" style={{ fontSize: '12px' }}>Min Reports</label>
											<input
												type="number"
												className="input"
												min="0"
												placeholder="e.g., 5"
												value={filters.providers.abuseipdb.minReports ?? ''}
												onChange={(e) => onChange({
													...filters,
													providers: {
														...filters.providers,
														abuseipdb: {
															...filters.providers.abuseipdb,
															enabled: true,
															minReports: e.target.value ? Number(e.target.value) : undefined
														}
													}
												})}
											/>
										</div>
									</div>
								)}
							</div>
							
							{/* OTX */}
							<div className="card" style={{ padding: '12px' }}>
								<label className="provider-checkbox" style={{ marginBottom: '8px' }}>
									<input
										type="checkbox"
										checked={filters.providers.otx?.enabled || false}
										onChange={(e) => onChange({
											...filters,
											providers: {
												...filters.providers,
												otx: {
													...filters.providers.otx,
													enabled: e.target.checked
												}
											}
										})}
									/>
									<span style={{ fontWeight: 600 }}>OTX (AlienVault)</span>
								</label>
								{filters.providers.otx?.enabled && (
									<div style={{ marginLeft: '24px' }}>
										<label className="label" style={{ fontSize: '12px' }}>Min Pulses</label>
										<input
											type="number"
											className="input"
											min="0"
											placeholder="e.g., 1"
											value={filters.providers.otx.minPulses ?? ''}
											onChange={(e) => onChange({
												...filters,
												providers: {
													...filters.providers,
													otx: {
														...filters.providers.otx,
														enabled: true,
														minPulses: e.target.value ? Number(e.target.value) : undefined
													}
												}
											})}
										/>
									</div>
								)}
							</div>
							
							{/* ThreatFox */}
							<div className="card" style={{ padding: '12px' }}>
								<label className="provider-checkbox" style={{ marginBottom: '8px' }}>
									<input
										type="checkbox"
										checked={filters.providers.threatfox?.enabled || false}
										onChange={(e) => onChange({
											...filters,
											providers: {
												...filters.providers,
												threatfox: {
													...filters.providers.threatfox,
													enabled: e.target.checked
												}
											}
										})}
									/>
									<span style={{ fontWeight: 600 }}>ThreatFox</span>
								</label>
								{filters.providers.threatfox?.enabled && (
									<div style={{ marginLeft: '24px' }}>
										<label className="label" style={{ fontSize: '12px' }}>Min Hits</label>
										<input
											type="number"
											className="input"
											min="0"
											placeholder="e.g., 1"
											value={filters.providers.threatfox.minHits ?? ''}
											onChange={(e) => onChange({
												...filters,
												providers: {
													...filters.providers,
													threatfox: {
														...filters.providers.threatfox,
														enabled: true,
														minHits: e.target.value ? Number(e.target.value) : undefined
													}
												}
											})}
										/>
									</div>
								)}
							</div>
						</div>
					)}
					
					{/* Presets Tab */}
					{activeTab === 'presets' && (
						<div style={{ display: 'grid', gap: '12px' }}>
							{FILTER_PRESETS.map(preset => (
								<div 
									key={preset.id}
									className="card"
									style={{ 
										padding: '12px',
										cursor: 'pointer',
										border: '1px solid var(--border-primary)',
										transition: 'all 0.2s'
									}}
									onClick={() => handlePreset(preset)}
								>
									<div style={{ fontWeight: 600, marginBottom: '4px' }}>{preset.name}</div>
									<div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
										{preset.description}
									</div>
								</div>
							))}
						</div>
					)}
				</div>
			)}
		</div>
	)
}

