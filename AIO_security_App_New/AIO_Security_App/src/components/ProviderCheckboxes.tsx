import React from 'react'
import type { ProviderSelection } from '../types'

interface Props {
	value: ProviderSelection
	onChange: (v: ProviderSelection) => void
}

export default function ProviderCheckboxes({ value, onChange }: Props) {
	function toggle(key: keyof ProviderSelection) {
		onChange({ ...value, [key]: !value[key] })
	}

	return (
		<div style={{ display: 'grid', gap: '8px' }}>
			{Object.entries(value).map(([key, checked]) => (
				<label key={key} className="provider-checkbox">
					<input
						type="checkbox"
						checked={checked}
						onChange={() => toggle(key as keyof ProviderSelection)}
					/>
					<span>{key === 'virustotal' ? 'VirusTotal' : 
						   key === 'abuseipdb' ? 'AbuseIPDB' : 
						   key === 'otx' ? 'OTX' : 'ThreatFox'}</span>
				</label>
			))}
		</div>
	)
} 