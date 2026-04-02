import React, { useEffect, useState } from 'react'
import type { ApiKeys, SandboxSettings } from '../types'
import { useToast } from '../context/ToastContext'
import { useHotkeys } from '../hooks/useHotkeys'
import { RATE_LIMITS } from '../config'

export default function Settings(){
	const [keys, setKeys] = useState<ApiKeys>({})
	const [sandboxSettings, setSandboxSettings] = useState<SandboxSettings>({
		preferReputationFirst: true,
		allowThirdPartyUploads: false
	})
	const [saving, setSaving] = useState(false)
	const { push } = useToast()

	useEffect(()=>{ 
		void (async()=>{ 
			const [apiKeys, sbSettings] = await Promise.all([
				window.api.getSettings(),
				window.api.getSandboxSettings?.() || { preferReputationFirst: true, allowThirdPartyUploads: false }
			])
			setKeys(apiKeys)
			setSandboxSettings(sbSettings)
		})() 
	}, [])

	useHotkeys([
		{ combo:'ctrl+s', handler: () => onSave() }
	])

	async function onSave(){
		setSaving(true)
		try {
			await Promise.all([
				window.api.saveSettings(keys),
				window.api.saveSandboxSettings?.(sandboxSettings)
			])
			push({ kind:'success', title:'Saved', message:'Settings saved successfully.' })
		} catch (error) {
			push({ kind:'error', title:'Save failed', message:'Failed to save settings.' })
		} finally {
			setSaving(false)
		}
	}

	return (
		<div className="settings-container">
			<div className="card panel">
				<div className="card-header">
					<h2 className="card-title">API Configuration</h2>
				</div>
				
				<div className="settings-form">
					<div>
						<h3 style={{ color: 'var(--text-primary)', marginBottom: '16px', fontSize: '16px' }}>IOC Analysis Providers</h3>
						
						<div style={{ display: 'grid', gap: '16px' }}>
							<div>
								<label className="label">VirusTotal API Key</label>
								<input 
									className="input centered" 
									value={keys.virustotal||''} 
									onChange={e=>setKeys({...keys, virustotal:e.target.value})} 
									placeholder="vt_xxx" 
								/>
								<div className="hint">Get your free API key from virustotal.com</div>
							</div>
							
							<div>
								<label className="label">AbuseIPDB API Key</label>
								<input 
									className="input centered" 
									value={keys.abuseipdb||''} 
									onChange={e=>setKeys({...keys, abuseipdb:e.target.value})} 
									placeholder="xxxxxxxx" 
								/>
								<div className="hint">Free API available at abuseipdb.com</div>
							</div>
							
							<div>
								<label className="label">OTX API Key</label>
								<input 
									className="input centered" 
									value={keys.otx||''} 
									onChange={e=>setKeys({...keys, otx:e.target.value})} 
									placeholder="xxxxxxxx" 
								/>
								<div className="hint">Register at otx.alienvault.com for free access</div>
							</div>
							
							<div>
								<label className="label">ThreatFox API Key</label>
								<input 
									className="input centered" 
									value={keys.threatfox||''} 
									onChange={e=>setKeys({...keys, threatfox:e.target.value})} 
									placeholder="paste Auth-Key from auth.abuse.ch" 
								/>
								<div className="hint">Get a free Auth-Key at auth.abuse.ch to enable ThreatFox IOC lookups.</div>
							</div>
						</div>
					</div>

					<div style={{ marginTop: '32px' }}>
						<h3 style={{ color: 'var(--text-primary)', marginBottom: '16px', fontSize: '16px' }}>Sandbox Analysis Providers</h3>
						
						<div style={{ display: 'grid', gap: '16px' }}>
							<div>
								<label className="label">OPSWAT MetaDefender API Key</label>
								<input 
									className="input centered" 
									value={keys.metadefender||''} 
									onChange={e=>setKeys({...keys, metadefender:e.target.value})} 
									placeholder="xxxxxxxx" 
								/>
								<div className="hint">Get your API key from metadefender.opswat.com for multi-engine scanning</div>
							</div>
							
							<div>
								<label className="label">urlscan.io API Key (Optional)</label>
								<input 
									className="input centered" 
									value={keys.urlscan||''} 
									onChange={e=>setKeys({...keys, urlscan:e.target.value})} 
									placeholder="xxxxxxxx" 
								/>
								<div className="hint">Optional: Improves rate limits for URL reputation lookups</div>
							</div>
						</div>
					</div>

					{/* Sandbox Preferences removed; defaults enforced */}
					<div style={{ marginTop: '32px' }}>
						<h3 style={{ color: 'var(--text-primary)', marginBottom: '16px', fontSize: '16px' }}>Sandbox Preferences</h3>
						<div style={{
							padding: '12px',
							background: 'rgba(245, 158, 11, 0.1)',
							borderRadius: '8px',
							border: '1px solid rgba(245, 158, 11, 0.3)',
							fontSize: '13px',
							color: 'var(--warning)'
						}}>
							Warning: When uploading files to third-party sandboxes, they may become publicly accessible. Only enable this for non-sensitive files.
						</div>
					</div>
				</div>
				
				<div className="settings-buttons">
					<button className="button primary" onClick={onSave} disabled={saving}>
						{saving ? (
							<>
								<span className="spinner" style={{ width: '16px', height: '16px' }}></span>
								Saving...
							</>
						) : (
							<>
								Save
							</>
						)}
					</button>
				</div>
			</div>

			{/* API Limits panel */}
			<div className="card panel" style={{ marginTop: '24px' }}>
				<div className="card-header">
					<h3 className="card-title">API Limits (reference)</h3>
				</div>
				<div style={{ padding: '12px', display: 'grid', gap: '8px' }}>
					{RATE_LIMITS.map(r => (
						<div key={r.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', border: '1px solid var(--border-primary)', borderRadius: '8px', padding: '10px 12px', background: 'var(--surface-secondary)' }}>
							<div>
								<div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{r.name}</div>
								<div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{r.summary}</div>
							</div>
							<a href={r.docsUrl} target="_blank" rel="noopener noreferrer" className="button ghost" style={{ fontSize: '12px' }}>
								Docs
							</a>
						</div>
					))}
					<LiveRateLimits />
					<div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
						Note: These are approximate and may change; refer to provider docs for current limits.
					</div>
				</div>
			</div>
		</div>
	)
}

function LiveRateLimits(){
	const [snapshot, setSnapshot] = React.useState<Record<string, { remaining?: number; resetAt?: number; lastSeen?: number }>>({})
	React.useEffect(() => {
		let mounted = true
		const tick = async () => {
			try{
				const s = await window.api.getRateLimits?.()
				if (mounted && s) setSnapshot(s)
			}catch{}
		}
		void tick()
		const id = setInterval(() => void tick(), 3000)
		return () => { mounted = false; clearInterval(id) }
	}, [])
	const items = Object.entries(snapshot)
	if (!items.length) return null
	return (
		<div style={{ marginTop: '12px', display: 'grid', gap: '6px' }}>
			<div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Live remaining (best-effort):</div>
			{items.map(([key, v]) => (
				<div key={key} style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
					{key}: {typeof v.remaining === 'number' ? v.remaining : '—'}{v.resetAt ? ` (resets in ${Math.max(0, Math.round((v.resetAt - Date.now())/1000))}s)` : ''}
				</div>
			))}
		</div>
	)
} 