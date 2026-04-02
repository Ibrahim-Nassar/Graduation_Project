import React, { useState } from 'react'

interface CollapsibleSectionProps {
	title: string
	children: React.ReactNode
	defaultOpen?: boolean
}

function CollapsibleSection({ title, children, defaultOpen = false }: CollapsibleSectionProps) {
	const [isOpen, setIsOpen] = useState(defaultOpen)

	return (
		<div className={`collapsible ${isOpen ? 'open' : ''}`}>
			<button 
				className="collapsible-header"
				onClick={() => setIsOpen(!isOpen)}
			>
				<span className="section-title">{title}</span>
				<span className="collapsible-icon">{isOpen ? '−' : '+'}</span>
			</button>
			{isOpen && (
				<div className="collapsible-content">
					{children}
				</div>
			)}
		</div>
	)
}

export default function Help(){
	return (
		<div style={{ maxWidth: '900px', margin: '0 auto', padding: '24px' }}>
			<div className="card panel">
				<div className="card-header">
					<h2 className="card-title">Help & Documentation</h2>
				</div>

				<div style={{ display: 'grid', gap: '20px' }}>
					<CollapsibleSection title="Getting Started" defaultOpen={true}>
						<p>IOC Checker helps you analyze Indicators of Compromise (IOCs) using multiple threat intelligence providers. Simply enter your IOCs and select which providers to query.</p>
						
						<div className="card">
							<h4>Quick Start:</h4>
							<ol>
								<li>Enter IOCs in the input field (one per line)</li>
								<li>Select your preferred threat intelligence providers</li>
								<li>Click "Analyze IOCs" to start the scan</li>
								<li>Review results in the table and detailed analysis panel</li>
							</ol>
						</div>
					</CollapsibleSection>

					<CollapsibleSection title="Supported IOC Types">
						<div style={{ display: 'grid', gap: '16px' }}>
							<div className="card">
								<h4>IP Addresses</h4>
								<p>Both IPv4 and IPv6 addresses are supported.</p>
								<div style={{ fontFamily: 'monospace', background: 'var(--surface-secondary)', padding: '8px', borderRadius: '4px' }}>
									192.168.1.1<br/>
									2001:db8::1
								</div>
							</div>

							<div className="card">
								<h4>Domain Names</h4>
								<p>Fully qualified domain names and subdomains.</p>
								<div style={{ fontFamily: 'monospace', background: 'var(--surface-secondary)', padding: '8px', borderRadius: '4px' }}>
									example.com<br/>
									malicious.subdomain.evil.org
								</div>
							</div>

							<div className="card">
								<h4>URLs</h4>
								<p>Complete URLs with protocols.</p>
								<div style={{ fontFamily: 'monospace', background: 'var(--surface-secondary)', padding: '8px', borderRadius: '4px' }}>
									https://example.com/malicious/path<br/>
									http://suspicious-site.com
								</div>
							</div>

							<div className="card">
								<h4>File Hashes</h4>
								<p>MD5, SHA-1, and SHA-256 hashes.</p>
								<div style={{ fontFamily: 'monospace', background: 'var(--surface-secondary)', padding: '8px', borderRadius: '4px' }}>
									5d41402abc4b2a76b9719d911017c592<br/>
									aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d<br/>
									e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
								</div>
							</div>
						</div>
					</CollapsibleSection>

					<CollapsibleSection title="Threat Intelligence Providers">
						<div style={{ display: 'grid', gap: '16px' }}>
							<div className="card">
								<h4>VirusTotal</h4>
								<span className="badge clean">Free Tier Available</span>
								<p>Multi-engine antivirus scanning and URL/file analysis. Provides detection ratios from 70+ antivirus engines.</p>
								<p><strong>Best for:</strong> File hash analysis, URL reputation, comprehensive malware detection</p>
							</div>

							<div className="card">
								<h4>AbuseIPDB</h4>
								<span className="badge clean">Free Tier Available</span>
								<p>IP address reputation and abuse reporting database. Specializes in identifying malicious IP addresses.</p>
								<p><strong>Best for:</strong> IP reputation, abuse confidence scores, geographic analysis</p>
							</div>

							<div className="card">
								<h4>AlienVault OTX</h4>
								<span className="badge clean">Free</span>
								<p>Open Threat Exchange - collaborative threat intelligence platform with community-driven IOC data.</p>
								<p><strong>Best for:</strong> Community intelligence, threat context, campaign attribution</p>
							</div>

							<div className="card">
								<h4>ThreatFox</h4>
								<span className="badge clean">Free</span>
								<p>IOC database focused on malware families and campaigns, maintained by abuse.ch.</p>
								<p><strong>Best for:</strong> Malware family identification, campaign tracking, fresh IOCs</p>
							</div>
						</div>
					</CollapsibleSection>

					<CollapsibleSection title="Keyboard Shortcuts">
						<div style={{ display: 'grid', gap: '12px' }}>
							<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
								<span>Start Analysis</span>
								<span className="kbd">Ctrl + Enter</span>
							</div>
							<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
								<span>Export Results</span>
								<span className="kbd">Ctrl + S</span>
							</div>
							<div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
								<span>Cancel Scan</span>
								<span className="kbd">Esc</span>
							</div>
						</div>
					</CollapsibleSection>

					<CollapsibleSection title="Tips & Best Practices">
						<div style={{ display: 'grid', gap: '16px' }}>
							<div className="card">
								<h4>Input Tips</h4>
								<ul>
									<li>Enter one IOC per line for best results</li>
									<li>Mixed IOC types in a single analysis are supported</li>
									<li>Use drag & drop for text files containing IOCs</li>
									<li>Remove any surrounding whitespace or quotes</li>
								</ul>
							</div>

							<div className="card">
								<h4>Provider Selection</h4>
								<ul>
									<li>Enable multiple providers for comprehensive analysis</li>
									<li>Different providers excel at different IOC types</li>
									<li>Consider rate limits when analyzing large datasets</li>
									<li>Free tiers are sufficient for most use cases</li>
								</ul>
							</div>

							<div className="card">
								<h4>Result Interpretation</h4>
								<ul>
									<li>Higher scores indicate greater threat confidence</li>
									<li>Check multiple providers for consensus</li>
									<li>Review detailed analysis for context</li>
									<li>Consider false positives in automated systems</li>
								</ul>
							</div>
						</div>
					</CollapsibleSection>
				</div>
			</div>
		</div>
	)
} 