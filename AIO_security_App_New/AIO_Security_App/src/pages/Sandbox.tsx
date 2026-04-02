import React, { useState, useRef, useEffect } from 'react'
import type { SandboxProviderSelection, SandboxSettings, SandboxResult, SandboxJobStage, ProviderResult } from '../types'
import { useToast } from '../context/ToastContext'
import { useHotkeys } from '../hooks/useHotkeys'
import { useDragDrop } from '../hooks/useDragDrop'
import { formatFileSize } from '../utils/formatting'

const defaultProviders: SandboxProviderSelection = {
	virustotal: true,
	metadefender: true,
	urlscan: true
}

export default function Sandbox(){
	const [selectedFile, setSelectedFile] = useState<{ path: string; name: string; size: number } | null>(null)
	const [urlInput, setUrlInput] = useState('')
	const [analysisType, setAnalysisType] = useState<'file' | 'url'>('file')
	const [providers, setProviders] = useState<SandboxProviderSelection>(defaultProviders)
	const [settings, setSettings] = useState<SandboxSettings>({
		preferReputationFirst: true,
		allowThirdPartyUploads: false
	})
	const [result, setResult] = useState<SandboxResult | null>(null)
	const [busy, setBusy] = useState(false)
	const [jobStages, setJobStages] = useState<Record<string, SandboxJobStage>>({})
	const jobIdRef = useRef('')
	const mountedRef = useRef(true)
	const progressUnsubRef = useRef<null | (() => void)>(null)
	const { push } = useToast()

	// Restore previous state on mount (persist across tab navigations)
	useEffect(() => {
		mountedRef.current = true
		
		// Load settings
		const loadSettings = async () => {
			try {
				const sandboxSettings = await window.api.getSandboxSettings?.()
				if (sandboxSettings) {
					setSettings(sandboxSettings)
				}
			} catch (error) {
				console.warn('Failed to load sandbox settings:', error)
			}
		}
		void loadSettings()
		
		// Restore state from sessionStorage
		try {
			const raw = sessionStorage.getItem('sandboxState')
			if (raw) {
				const s = JSON.parse(raw)
				if (s.selectedFile) setSelectedFile(s.selectedFile)
				if (typeof s.urlInput === 'string') setUrlInput(s.urlInput)
				if (s.analysisType) setAnalysisType(s.analysisType)
				if (s.providers) setProviders(s.providers)
				if (s.result) setResult(s.result)
				if (s.jobStages) setJobStages(s.jobStages)
				if (s.busy) setBusy(true)
				if (typeof s.jobId === 'string') jobIdRef.current = s.jobId
			}
		} catch (error) {
			console.warn('Failed to restore sandbox state:', error)
		}
		
		return () => {
			mountedRef.current = false
			// Detach any active progress listener to prevent setState after unmount
			try { progressUnsubRef.current?.() } catch {}
			progressUnsubRef.current = null
		}
	}, [])
	
	// Persist state whenever it changes (debounced)
	useEffect(() => {
		const timeoutId = setTimeout(() => {
			const state = {
				selectedFile,
				urlInput,
				analysisType,
				providers,
				result,
				jobStages,
				busy,
				jobId: jobIdRef.current,
			}
			try { sessionStorage.setItem('sandboxState', JSON.stringify(state)) } catch {}
		}, 500) // Debounce for 500ms
		
		return () => clearTimeout(timeoutId)
	}, [selectedFile, urlInput, analysisType, providers, result, jobStages, busy])
	
	// Re-attach progress listener if returning while a job is active
	useEffect(() => {
		if (!busy || !jobIdRef.current) return
		
		const removeProgressListener = window.api.onSandboxProgress((data) => {
			if (data.jobId === jobIdRef.current) {
				if (mountedRef.current) {
					if (data.stage) {
						setJobStages(prev => ({
							...prev,
							[data.provider || 'general']: data.stage
						}))
					}
					if (data.result) {
						setResult(prev => prev ? {
							...prev,
							providers: {
								...prev.providers,
								[data.provider!]: data.result
							}
						} : null)
					}
				}
			}
		})
		
		progressUnsubRef.current = removeProgressListener
		return () => removeProgressListener()
	}, [busy])

	useHotkeys([
		{ combo: 'ctrl+enter', handler: () => onAnalyze() },
		{ combo: 'esc', handler: () => onCancel() },
	])

	// Drag and drop handlers using custom hook
	const { isDragOver, handleDragOver, handleDragLeave, handleDrop } = useDragDrop({
		onDrop: (file: File) => {
			setSelectedFile({
				path: (file as unknown as { path?: string }).path || '',
				name: file.name || 'Unknown',
				size: typeof file.size === 'number' ? file.size : 0
			})
			setAnalysisType('file')
			push({ kind: 'success', title: 'File loaded', message: `Loaded ${file.name || 'file'}` })
		}
	})

	const onSelectFile = async () => {
		try {
			const result = await window.api.selectFile()
			if (!result.canceled && result.filePath) {
				setSelectedFile({
					path: result.filePath,
					name: result.fileName || 'Unknown',
					size: result.fileSize || 0
				})
				setAnalysisType('file')
			}
		} catch (error: unknown) {
			push({ kind: 'error', title: 'File selection failed', message: error instanceof Error ? error.message : String(error) })
		}
	}

	const onAnalyze = async () => {
		// Validation
		if (analysisType === 'file' && !selectedFile) {
			push({ kind: 'error', title: 'No file selected', message: 'Please select a file for analysis.' })
			return
		}
		if (analysisType === 'url' && !urlInput.trim()) {
			push({ kind: 'error', title: 'No URL entered', message: 'Please enter a URL for analysis.' })
			return
		}
		if (!Object.values(providers).some(Boolean)) {
			push({ kind: 'error', title: 'No providers selected', message: 'Please select at least one analysis provider.' })
			return
		}

		// Check consent for uploads
		if (analysisType === 'file' && !settings.allowThirdPartyUploads) {
			const hasUploadProviders = providers.metadefender
			if (hasUploadProviders) {
				push({ 
					kind: 'error', 
					title: 'Upload consent required', 
					message: 'Third-party uploads not allowed. Enable in Settings or disable upload providers.' 
				})
				return
			}
		}

		setBusy(true)
		setResult(null)
		setJobStages({})

		const jobId = Math.random().toString(36).slice(2)
		jobIdRef.current = jobId

		try {
			const input = analysisType === 'file' ? selectedFile! : urlInput.trim()
			const scanResult = await window.api.scanSandbox({
				type: analysisType,
				input,
				providers,
				settings,
				jobId
			})
			
			setResult(scanResult)
			push({ 
				kind: 'success', 
				title: 'Analysis completed', 
				message: `${analysisType === 'file' ? 'File' : 'URL'} analysis completed successfully.` 
			})
		} catch (error: unknown) {
			push({ kind: 'error', title: 'Analysis failed', message: error instanceof Error ? error.message : String(error) })
		} finally {
			setBusy(false)
		}
	}

	const onCancel = async () => {
		const id = jobIdRef.current
		if (id && busy) {
			await window.api.cancelScan(id)
			setBusy(false)
			setJobStages({})
			push({ kind: 'info', title: 'Analysis cancelled', message: 'The analysis has been stopped.' })
		}
	}

	const onExportJson = async () => {
		if (!result) {
			push({ kind: 'info', title: 'No results', message: 'Run an analysis first to export results.' })
			return
		}
		const res = await window.api.exportSandboxJson(result)
		if (!res.canceled) {
			push({ kind: 'success', title: 'Export successful', message: 'Results saved to JSON file.' })
		}
	}

	const onCopySummary = async () => {
		if (!result) {
			push({ kind: 'info', title: 'No results', message: 'Run an analysis first to copy summary.' })
			return
		}
		
		const lines = [
			`Input: ${result.input}`,
			`Type: ${result.type}`,
			`Status: ${result.status}`,
			`Score: ${result.score}`,
			`Verdict: ${result.verdict || 'Unknown'}`,
			''
		]
		
		if (result.fileInfo) {
			lines.push('File Information:')
			lines.push(`  Name: ${result.fileInfo.name}`)
			lines.push(`  Size: ${formatFileSize(result.fileInfo.size)}`)
			if (result.fileInfo.sha256) {
				lines.push(`  SHA256: ${result.fileInfo.sha256}`)
			}
			lines.push('')
		}
		
		lines.push('Provider Results:')
		Object.values(result.providers).forEach(provider => {
			if (provider) {
				lines.push(`- ${provider.provider}: ${provider.status} (Score: ${provider.score})`)
				if (provider.evidence) {
					provider.evidence.slice(0, 3).forEach(evidence => {
						lines.push(`    ${evidence}`)
					})
				}
			}
		})
		
		await window.api.copyToClipboard(lines.join('\n'))
		push({ kind: 'success', title: 'Copied to clipboard', message: 'Summary has been copied.' })
	}

	const getStatusColor = (status: string) => {
		switch (status) {
			case 'malicious': return 'var(--danger)'
			case 'suspicious': return 'var(--warning)'
			case 'clean': return 'var(--success)'
			default: return 'var(--text-secondary)'
		}
	}

	const getProgressColor = (stage: string) => {
		switch (stage) {
			case 'uploading': return 'var(--info)'
			case 'analyzing': return 'var(--warning)'
			case 'completed': return 'var(--success)'
			case 'failed': return 'var(--danger)'
			default: return 'var(--text-secondary)'
		}
	}

	return (
		<div style={{
			display: 'grid',
			gridTemplateColumns: '1fr 400px',
			gap: '24px',
			height: 'calc(100vh - 80px)',
			padding: '24px',
			maxWidth: '1600px',
			margin: '0 auto'
		}}>
			{/* Main content area */}
			<div style={{ display: 'grid', gridTemplateRows: 'auto auto 1fr auto', gap: '24px' }}>
				{/* Input section */}
				<div className="card panel">
					<div className="card-header">
						<h2 className="card-title">Sandbox Analysis</h2>
					</div>

					{/* Analysis type selector */}
					<div style={{ marginBottom: '20px' }}>
						<div style={{ display: 'flex', gap: '12px', marginBottom: '16px' }}>
							<label className="provider-checkbox">
								<input
									type="radio"
									name="analysisType"
									checked={analysisType === 'file'}
									onChange={() => setAnalysisType('file')}
								/>
								<span>File Analysis</span>
							</label>
							<label className="provider-checkbox">
								<input
									type="radio"
									name="analysisType"
									checked={analysisType === 'url'}
									onChange={() => setAnalysisType('url')}
								/>
								<span>URL Analysis</span>
							</label>
						</div>
					</div>

					{/* File input */}
					{analysisType === 'file' && (
						<div style={{ marginBottom: '20px' }}>
							<label className="label">File Selection</label>
							{selectedFile ? (
								<div style={{
									padding: '16px',
									background: 'var(--surface-secondary)',
									borderRadius: '10px',
									border: '1px solid var(--border-primary)'
								}}>
									<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
										<div>
											<div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{selectedFile.name}</div>
											<div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
												{formatFileSize(selectedFile.size)}
											</div>
										</div>
										<button className="button secondary" onClick={onSelectFile}>
											Change File
										</button>
									</div>
								</div>
							) : (
								<div
									className={`textarea ${isDragOver ? 'drop-zone' : ''}`}
									onDragOver={handleDragOver}
									onDragLeave={handleDragLeave}
									onDrop={handleDrop}
									onClick={onSelectFile}
									style={{
										minHeight: '120px',
										display: 'flex',
										alignItems: 'center',
										justifyContent: 'center',
										cursor: 'pointer',
										textAlign: 'center',
										flexDirection: 'column',
										gap: '8px'
									}}
								>
									<div style={{ fontSize: '24px' }}>FILE</div>
									<div>Click to select a file or drag & drop here</div>
									<div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
										Supports executables, documents, archives, and more
									</div>
								</div>
							)}
						</div>
					)}

					{/* URL input */}
					{analysisType === 'url' && (
						<div style={{ marginBottom: '20px' }}>
							<label className="label">URL Input</label>
							<input
								className="input"
								type="url"
								placeholder="https://example.com"
								value={urlInput}
								onChange={e => setUrlInput(e.target.value)}
							/>
						</div>
					)}



					{/* Action buttons */}
					<div style={{ display: 'flex', gap: '12px' }}>
						<button
							className="button primary"
							onClick={onAnalyze}
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
									Analyze {analysisType === 'file' ? 'File' : 'URL'}
								</>
							)}
						</button>
						{busy && (
							<button className="button secondary" onClick={onCancel}>
								Cancel
							</button>
						)}
					</div>
				</div>

				{/* Provider selection */}
				<div className="card panel">
					<div className="card-header">
						<h3 className="card-title">Analysis Providers</h3>
					</div>
					<div style={{ display: 'grid', gap: '12px' }}>
						<label className="provider-checkbox">
							<input
								type="checkbox"
								checked={providers.virustotal}
								onChange={e => setProviders({ ...providers, virustotal: e.target.checked })}
							/>
							<span>VirusTotal - Multi-engine analysis</span>
						</label>
						<label className="provider-checkbox">
							<input
								type="checkbox"
								checked={providers.metadefender}
								onChange={e => setProviders({ ...providers, metadefender: e.target.checked })}
								disabled={analysisType === 'url'}
							/>
							<span>OPSWAT MetaDefender - Multi-engine scan (Files only)</span>
						</label>
						<label className="provider-checkbox">
							<input
								type="checkbox"
								checked={providers.urlscan}
								onChange={e => setProviders({ ...providers, urlscan: e.target.checked })}
								disabled={analysisType === 'file'}
							/>
							<span>urlscan.io - URL reputation (URLs only)</span>
						</label>
					</div>
				</div>

				{/* Job progress */}
				{busy && Object.keys(jobStages).length > 0 && (
					<div className="card panel">
						<div className="card-header">
							<h3 className="card-title">Analysis Progress</h3>
						</div>
						<div style={{ display: 'grid', gap: '12px' }}>
							{Object.entries(jobStages).map(([provider, stage]) => (
								<div key={provider} style={{
									display: 'flex',
									justifyContent: 'space-between',
									alignItems: 'center',
									padding: '12px',
									background: 'var(--surface-secondary)',
									borderRadius: '8px',
									border: '1px solid var(--border-primary)'
								}}>
									<span style={{ fontWeight: 600, textTransform: 'capitalize' }}>{provider}</span>
									<span style={{ 
										color: getProgressColor(stage.stage),
										display: 'flex',
										alignItems: 'center',
										gap: '8px'
									}}>
										{stage.stage === 'analyzing' && (
											<span className="spinner" style={{ width: '12px', height: '12px' }}></span>
										)}
										{stage.stage}
										{stage.progress && ` (${stage.progress}%)`}
									</span>
								</div>
							))}
						</div>
					</div>
				)}

				{/* Export buttons */}
				{result && (
					<div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
						<button className="button secondary" onClick={onExportJson}>
							Export JSON
						</button>
						<button className="button ghost" onClick={onCopySummary}>
							Copy Summary
						</button>
						<button className="button danger" onClick={() => {
							setResult(null)
							setJobStages({})
							setBusy(false)
							jobIdRef.current = ''
							try { sessionStorage.removeItem('sandboxState') } catch {}
						}}>
							Clear Results
						</button>
					</div>
				)}
			</div>

			{/* Results sidebar */}
			<div style={{ display: 'grid', gridTemplateRows: 'auto 1fr', gap: '24px' }}>
				{/* Overall verdict */}
				{result && (
					<div className="card panel">
						<div className="card-header">
							<h3 className="card-title">Overall Verdict</h3>
						</div>
						<div style={{
							padding: '16px',
							background: `${getStatusColor(result.status)}15`,
							borderRadius: '10px',
							border: `1px solid ${getStatusColor(result.status)}50`,
							textAlign: 'center'
						}}>
							<div style={{
								fontSize: '24px',
								fontWeight: 700,
								color: getStatusColor(result.status),
								textTransform: 'uppercase',
								marginBottom: '8px'
							}}>
								{result.status}
							</div>
							<div style={{ fontSize: '18px', fontWeight: 600, marginBottom: '8px' }}>
								Score: {result.score}/100
							</div>
							<div style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
								{result.verdict}
							</div>
						</div>
					</div>
				)}

				{/* Provider results - only show when there are results */}
				{result && (
					<div className="card panel" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
						<div className="card-header">
							<h3 className="card-title">Provider Results</h3>
						</div>
						<div style={{ flex: 1, overflow: 'auto' }}>
							<div style={{ display: 'grid', gap: '12px' }}>
								{Object.values(result.providers).map(provider => {
									if (!provider) return null
									return (
										<div key={provider.provider} style={{
											padding: '16px',
											background: 'var(--surface-secondary)',
											borderRadius: '10px',
											border: '1px solid var(--border-primary)'
										}}>
											<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
												<span style={{ fontWeight: 600, textTransform: 'capitalize' }}>
													{provider.provider}
												</span>
												<span style={{
													color: getStatusColor(provider.status),
													fontWeight: 600,
													fontSize: '12px',
													textTransform: 'uppercase'
												}}>
													{provider.status}
												</span>
											</div>
											<div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
												Score: {provider.score}/100
												{provider.latency_ms && ` • ${provider.latency_ms}ms`}
												{provider.cache_hit && ' • Cached'}
											</div>
											{provider.evidence && provider.evidence.length > 0 && (
												<div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
													{provider.evidence.slice(0, 3).map((evidence, i) => (
														<div key={i}>• {evidence}</div>
													))}
												</div>
											)}
											{provider.raw_ref && (
												<div style={{ marginTop: '8px' }}>
													<a
														href={provider.raw_ref}
														target="_blank"
														rel="noopener noreferrer"
														style={{
															color: 'var(--primary)',
															fontSize: '13px',
															textDecoration: 'none'
														}}
													>
														View Full Report
													</a>
												</div>
											)}
											{provider.error && (
												<div style={{
													color: 'var(--danger)',
													fontSize: '13px',
													marginTop: '8px',
													fontStyle: 'italic'
												}}>
													Error: {provider.error}
												</div>
											)}
										</div>
									)
								})}
							</div>
						</div>
					</div>
				)}
			</div>
		</div>
	)
} 