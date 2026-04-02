import React, { useMemo, useRef, useState, useCallback } from 'react'
import type { ProviderSelection, ProviderResult } from '../types'
import type { CaseIoc } from '../types/case'
import type { IocFilters } from '../types/filters'
import ProviderCheckboxes from '../components/ProviderCheckboxes'
import FilterPanel from '../components/FilterPanel'
import IocDetailPanel from '../components/IocDetailPanel'
import { toCsv } from '../utils/csv'
import { useToast } from '../context/ToastContext'
import { useHotkeys } from '../hooks/useHotkeys'
import { useDragDrop } from '../hooks/useDragDrop'
import { FLAGS } from '../flags'
import { extractIOCsFromText, extractIOCsWithContext, IocContext } from '../domain/ioc-detection'
import { LOG_TEMPLATES, autoDetectTemplate, getTemplateById } from '../domain/log-templates'
import { ocrImageToText } from '../utils/ocr'
import { detectIocType, IocType } from '../types/ioc'
import { DEFAULT_FILTERS } from '../types/filters'
import { filterIocResults } from '../utils/filter-iocs'

const defaultProviders: ProviderSelection = { virustotal: true, abuseipdb: true, otx: true, threatfox: true }

export default function Checker(){
	const [input, setInput] = useState('')
	const [providers, setProviders] = useState<ProviderSelection>(defaultProviders)
	const [results, setResults] = useState<CaseIoc[]>([])
	const [filters, setFilters] = useState<IocFilters>(DEFAULT_FILTERS)
	const [selectedTemplateId, setSelectedTemplateId] = useState<string>('auto')
	const [selectedIndex, setSelectedIndex] = useState<number>(-1)
	const [showDetailPanel, setShowDetailPanel] = useState(false)
	const [busy, setBusy] = useState(false)
	const [loadingProviders, setLoadingProviders] = useState<{[iocIndex: number]: {[provider: string]: boolean}}>({})
	const jobIdRef = useRef('')
	const progressUnsubRef = useRef<null | (() => void)>(null)
	const mountedRef = useRef(true)
	const { push } = useToast()

	// Extract IOCs with context based on selected template
	const parsedIocs = useMemo(() => {
		const parser = selectedTemplateId === 'auto' 
			? (line: string) => autoDetectTemplate(line)?.parse(line) || {}
			: (line: string) => getTemplateById(selectedTemplateId)?.parse(line) || {};
			
		return extractIOCsWithContext(input, parser);
	}, [input, selectedTemplateId]);
	
	// Apply filters to results
	const filteredResults = useMemo(() => filterIocResults(results, filters) as CaseIoc[], [results, filters])
	
	// Fix: Ensure selected index is within bounds of filtered results
	const selected = selectedIndex >= 0 && selectedIndex < filteredResults.length ? filteredResults[selectedIndex] : null

	// Derived: finished IOC count during an active run
	const finishedIocs = useMemo(() => {
		if (!busy) return 0
		let done = 0
		for (let i = 0; i < parsedIocs.length; i++){
			const pending = loadingProviders[i]
			if (pending && Object.keys(pending).length === 0) done++
		}
		return done
	}, [busy, loadingProviders, parsedIocs])
	const totalIocs = parsedIocs.length
	const percentDone = totalIocs > 0 ? Math.round((finishedIocs / totalIocs) * 100) : 0

	// Restore previous state on mount (persist across tab navigations)
	React.useEffect(() => {
		mountedRef.current = true
		try{
			const raw = sessionStorage.getItem('checkerState')
			if (raw){
				const s = JSON.parse(raw)
				if (typeof s.input === 'string') setInput(s.input)
				if (s.providers) setProviders(s.providers)
				if (Array.isArray(s.results)) setResults(s.results)
				if (s.filters) setFilters(s.filters)
				if (typeof s.selectedIndex === 'number') setSelectedIndex(s.selectedIndex)
				if (s.loadingProviders) setLoadingProviders(s.loadingProviders)
				if (s.busy) setBusy(true)
				if (typeof s.jobId === 'string') jobIdRef.current = s.jobId
				if (typeof s.selectedTemplateId === 'string') setSelectedTemplateId(s.selectedTemplateId)
			}
		}catch{}
		return () => {
			mountedRef.current = false
			try{ progressUnsubRef.current?.() }catch{}
			progressUnsubRef.current = null
		}
	// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [])

	// Persist state whenever it changes (debounced)
	React.useEffect(() => {
		const timeoutId = setTimeout(() => {
			const state = {
				input,
				providers,
				results,
				filters,
				selectedIndex,
				loadingProviders,
				busy,
				jobId: jobIdRef.current,
				selectedTemplateId
			}
			try{ sessionStorage.setItem('checkerState', JSON.stringify(state)) }catch{}
		}, 500)
		
		return () => clearTimeout(timeoutId)
	}, [input, providers, results, filters, selectedIndex, loadingProviders, busy, selectedTemplateId])

	// Re-attach progress listener if returning while a job is active
	React.useEffect(() => {
		if (!busy || !jobIdRef.current) return
		const removeProgressListener = window.api.onScanProgress((data) => {
			if (data.jobId === jobIdRef.current) {
				setResults(prevResults => {
					const newResults = [...prevResults]
					// Ensure the row exists
					if (!newResults[data.iocIndex]){
						const extracted = parsedIocs[data.iocIndex];
						const rawIoc = extracted?.value || `#${data.iocIndex+1}`;
						const iocType = extracted?.type || 'unknown';
						// Initialize with context
						newResults[data.iocIndex] = { 
							ioc: rawIoc, 
							type: iocType, 
							status: 'unknown', 
							score: 0, 
							providers: {},
							context: extracted?.context
						}
					} else {
						// Preserve context if already exists, or add it if missing (shouldn't happen if flow is correct)
						if (!newResults[data.iocIndex].context && parsedIocs[data.iocIndex]) {
							newResults[data.iocIndex].context = parsedIocs[data.iocIndex].context;
						}
					}

					newResults[data.iocIndex] = {
						...newResults[data.iocIndex]!,
						providers: {
							...(newResults[data.iocIndex]!.providers || {}),
							[data.provider]: data.result as ProviderResult
						}
					}
					// Recompute aggregates
					const providerArr = Object.values(newResults[data.iocIndex]!.providers || {}) as Array<{ status?: string; score?: number }>
					let finalStatus: 'unknown'|'malicious'|'suspicious'|'clean' = 'unknown'
					if (providerArr.some(p => p?.status === 'malicious')) finalStatus = 'malicious'
					else if (providerArr.some(p => p?.status === 'suspicious')) finalStatus = 'suspicious'
					else if (providerArr.some(p => p?.status === 'clean')) finalStatus = 'clean'
					const scores = providerArr.map(p => typeof p.score === 'number' ? p.score : null).filter((n): n is number => n !== null)
					const avgScore = scores.length ? Math.round(scores.reduce((a,b)=>a+b,0)/scores.length) : 0
					newResults[data.iocIndex] = { ...newResults[data.iocIndex]!, status: finalStatus, score: avgScore }
					return newResults
				})
				
				setLoadingProviders(prev => {
					const newLoading = { ...prev }
					if (newLoading[data.iocIndex]) {
						const newProviderLoading = { ...newLoading[data.iocIndex]! }
						delete newProviderLoading[data.provider]
						newLoading[data.iocIndex] = newProviderLoading
					}
					return newLoading
				})
			}
		})
		return () => removeProgressListener()
	}, [busy, parsedIocs])

	useHotkeys([
		{ combo: 'ctrl+enter', handler: () => onRun() },
		{ combo: 'ctrl+s', handler: () => onExportCsv() },
		{ combo: 'esc', handler: () => onCancel() },
	])

	const { isDragOver, handleDragOver, handleDragLeave, handleDrop } = useDragDrop({
		onDrop: useCallback((file: File) => {
			const reader = new FileReader()
			reader.onload = (event) => {
				const content = (event.target && typeof (event.target as FileReader).result === 'string') ? (event.target as FileReader).result as string : ''
				if (content) {
					if (FLAGS.smartIocExtraction) {
						const iocs = extractIOCsFromText(content)
						if (iocs.length) {
							setInput(prev => prev ? prev + '\n' + content : content) // Append content to preserve context
							push({ kind: 'success', title: 'File loaded', message: `Extracted ${iocs.length} IOC${iocs.length !== 1 ? 's' : ''}` })
						} else {
							push({ kind: 'info', title: 'No IOCs found', message: 'The dropped file did not contain recognizable IOCs.' })
						}
					} else {
						setInput(prev => prev ? prev + '\n' + content : content)
						push({ kind: 'success', title: 'File loaded', message: `Loaded 1 file` })
					}
				}
			}
			reader.readAsText(file as Blob)
		}, [push]),
		acceptedTypes: ['txt', 'csv', 'log']
	})

	async function onRun(){
		if (parsedIocs.length === 0) {
			push({ kind: 'error', title: 'No IOCs detected', message: 'Please enter valid IOCs in the input field.' })
			return
		}
		if (!Object.values(providers).some(Boolean)) {
			push({ kind: 'error', title: 'No providers selected', message: 'Please select at least one threat intelligence provider.' })
			return
		}
		setBusy(true)
		
		// Initialize results with context immediately
		const initialResults: CaseIoc[] = parsedIocs.map(extracted => ({
			ioc: extracted.value,
			type: extracted.type,
			status: 'unknown',
			score: 0,
			providers: {},
			context: extracted.context
		}));
		setResults(initialResults);
		
		setSelectedIndex(-1)
		setShowDetailPanel(false)
		
		const initialLoading: {[iocIndex: number]: {[provider: string]: boolean}} = {}
		parsedIocs.forEach((extracted, index) => {
			initialLoading[index] = {}
			const iocType = extracted.type
			if (iocType === 'unknown') return
			Object.entries(providers).forEach(([provider, enabled]) => {
				if (!enabled) return
				if (provider === 'abuseipdb' && iocType !== 'ip') return
				initialLoading[index]![provider] = true
			})
		})
		setLoadingProviders(initialLoading)

		const jobId = Math.random().toString(36).slice(2); jobIdRef.current = jobId
		
		// Progress listener is handled by useEffect
		// Kick off scan
		void window.api.scanIOCs({ iocs: parsedIocs.map(p => p.value), providers, jobId }).catch((e: unknown) => {
			const msg = e instanceof Error ? e.message : String(e)
			push({ kind:'error', title:'Scan failed', message: msg })
			setBusy(false)
		})
	}

	async function onCancel(){
		const id = jobIdRef.current
		if (id && busy){
			await window.api.cancelScan(id)
			setLoadingProviders({})
			push({ kind:'info', title:'Scan cancelled', message:'The scan has been stopped.' })
			setBusy(false)
		}
	}

	async function onExportCsv(){
		if (!filteredResults.length) {
			push({ kind: 'info', title: 'No results', message: 'Run a scan first to export results.' })
			return
		}
		const csv = toCsv(filteredResults)
		const res = await window.api.exportCsv(csv)
		if (!res.canceled) {
			push({ kind: 'success', title: 'Export successful', message: `Exported ${filteredResults.length} IOCs.` })
		}
	}

	return (
		<div style={{
			display: 'grid',
			gridTemplateColumns: '1fr 400px',
			gap: '24px',
			height: 'calc(100vh - 80px)',
			padding: '24px',
			maxWidth: '1400px',
			margin: '0 auto'
		}}>
			<div style={{ display: 'grid', gridTemplateRows: 'auto 1fr auto', gap: '24px' }}>
				<div className="card panel">
					<div className="card-header">
						<h2 className="card-title">IOC Analysis</h2>
						<select 
							value={selectedTemplateId} 
							onChange={(e) => setSelectedTemplateId(e.target.value)}
							className="select"
							style={{ marginLeft: 'auto', width: '200px' }}
						>
							<option value="auto">Auto-Detect Log Format</option>
							{LOG_TEMPLATES.map(t => (
								<option key={t.id} value={t.id}>{t.name}</option>
							))}
						</select>
					</div>
					<div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '24px', alignItems: 'start' }}>
						<div style={{ display: 'grid', gap: '12px' }}>
							<label className="label">Log / IOC Input</label>
								<textarea
								className={`textarea ${isDragOver ? 'drop-zone' : ''}`}
								placeholder="Paste raw logs or IOC list here..."
								value={input}
									onChange={e => setInput(e.target.value)}
									onPaste={async (e) => {
										// Handle paste logic (omitted for brevity, same as before)
										try {
											const items = e.clipboardData?.items
											if (!items) return
											for (let i = 0; i < items.length; i++){
												const item = items[i]
												if (item.type && item.type.startsWith('image/')){
													e.preventDefault()
													const file = item.getAsFile()
													if (!file) return
													let text = await ocrImageToText(file)
													if (!text && window.api.pasteImageToText){
														text = await window.api.pasteImageToText().catch(() => '')
													}
													if (text){
														// Just append text, let extraction logic handle it
														setInput(prev => prev ? prev + '\n' + text : text)
														push({ kind: 'success', title: 'Image parsed', message: 'Text extracted from image' })
													}
													return
												}
											}
										}catch{}
									}}
								onDragOver={handleDragOver}
								onDragLeave={handleDragLeave}
								onDrop={handleDrop}
								style={{ minHeight: '160px', resize: 'vertical', fontFamily: 'monospace', fontSize: '12px' }}
							/>
							<div className="ioc-count">
								{parsedIocs.length} IOC{parsedIocs.length !== 1 ? 's' : ''} detected
							</div>
						</div>
						<div style={{ display: 'grid', gap: '16px' }}>
							<div>
								<label className="label">Threat Intelligence Providers</label>
								<ProviderCheckboxes value={providers} onChange={setProviders} />
							</div>
							<div style={{ display: 'flex', gap: '12px' }}>
								<button
									className="button primary"
									onClick={onRun}
									disabled={busy}
									style={{ flex: 1 }}
								>
									{busy ? (
										<>
											<span className="spinner" style={{ width: '16px', height: '16px' }}></span>
											Analyzing...
										</>
									) : (
										<>
											Analyze IOCs
										</>
									)}
								</button>
								{busy && (
									<button className="button secondary" onClick={onCancel}>
										Cancel
									</button>
								)}
							</div>
							{busy && totalIocs > 0 && (
								<div style={{ marginTop: '8px' }}>
									<div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
										Completed {finishedIocs} / {totalIocs} IOCs ({percentDone}%)
									</div>
									<div style={{ height: '6px', background: 'var(--surface-secondary)', border: '1px solid var(--border-primary)', borderRadius: '999px', overflow: 'hidden' }}>
										<div style={{ width: `${percentDone}%`, height: '100%', background: 'var(--primary)' }} />
									</div>
								</div>
							)}
						</div>
					</div>
				</div>
				
				{/* Results Table */}
				{filteredResults.length > 0 && (
					<div className="card panel" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
						<div className="card-header">
							<h3 className="card-title">Results ({filteredResults.length})</h3>
						</div>
						<div style={{ flex: 1, overflow: 'visible' }}>
							<table className="table">
								<thead>
									<tr>
										<th>IOC</th>
										<th>Type</th>
										<th>Status</th>
										<th>Providers</th>
									</tr>
								</thead>
								<tbody>
									{filteredResults.map((row, i) => (
										<tr 
											key={i} 
											className={selectedIndex === i ? 'selected' : ''} 
											onClick={() => {
												setSelectedIndex(i)
												setShowDetailPanel(true)
											}}
											style={{ cursor: 'pointer' }}
										>
											<td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{row.ioc}</td>
											<td>
												<span className={`badge ${row.type}`}>{row.type}</span>
											</td>
											<td>
												<span className={`badge ${row.status}`}>{row.status}</span>
											</td>
											<td>
												<div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
													{Object.entries(row.providers).map(([provider, result]) => {
														if (!result) return null
														const isLoading = loadingProviders[i]?.[provider]
														return (
															<span 
																key={provider} 
																className={`badge info ${isLoading ? 'loading' : ''}`}
																title={`${provider}: ${result.status}`}
																style={{ fontSize: '11px' }}
															>
																{isLoading ? (
																	<span className="spinner" style={{ width: '10px', height: '10px' }}></span>
																) : (
																	provider
																)}
															</span>
														)
													})}
												</div>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					</div>
				)}
				
				{results.length > 0 && (
					<div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
						<button className="button secondary" onClick={onExportCsv}>
							Export CSV ({filteredResults.length})
						</button>
						<button className="button danger" onClick={() => { 
							setResults([])
							setFilters(DEFAULT_FILTERS)
							setSelectedIndex(-1)
							setShowDetailPanel(false)
							setLoadingProviders({})
							setBusy(false)
							jobIdRef.current=''
							try{ sessionStorage.removeItem('checkerState') }catch{} 
						}}>
							Clear All
						</button>
					</div>
				)}
			</div>
			
			{/* Right Column - Help or Info */}
			<div style={{ display: 'grid', gridTemplateRows: 'auto 1fr', gap: '24px' }}>
				<div className="card panel">
					<div className="card-header">
						<h3 className="card-title">Log Parsing</h3>
					</div>
					<div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
						<p>
							Select a template to extract contextual data from your logs automatically.
						</p>
						<div style={{ background: 'rgba(59, 130, 246, 0.1)', padding: '8px', borderRadius: '4px', marginTop: '8px' }}>
							<strong>Current Mode:</strong> {selectedTemplateId === 'auto' ? 'Auto-Detect' : LOG_TEMPLATES.find(t => t.id === selectedTemplateId)?.name}
						</div>
					</div>
				</div>
			</div>

			{/* Detail Panel Overlay */}
			{showDetailPanel && selected && (
				<IocDetailPanel 
					ioc={selected} 
					onClose={() => setShowDetailPanel(false)}
				/>
			)}
		</div>
	)
}
