export type ProviderKey = 'virustotal' | 'abuseipdb' | 'otx' | 'threatfox' | 'metadefender' | 'urlscan'

export type IocType = 'ip' | 'domain' | 'url' | 'hash' | 'unknown'

export type SandboxInputType = 'file' | 'url'

export interface ProviderSelection {
	virustotal: boolean
	abuseipdb: boolean
	otx: boolean
	threatfox: boolean
}

export interface SandboxProviderSelection {
	virustotal: boolean
	metadefender: boolean
	urlscan: boolean
}

export interface ApiKeys {
	virustotal?: string
	abuseipdb?: string
	otx?: string
	threatfox?: string
	metadefender?: string
	urlscan?: string
}

export interface SandboxSettings {
	preferReputationFirst: boolean
	allowThirdPartyUploads: boolean
}

export interface ProviderResult {
	provider: ProviderKey
	status: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error'
	score: number
	details?: unknown
	error?: string
	latency_ms?: number
	cache_hit?: boolean
	evidence?: string[]
	raw_ref?: string
}

export interface IocResult {
	ioc: string
	type: IocType
	status: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'invalid' | 'error'
	score: number
	providers: Partial<Record<ProviderKey, ProviderResult>>
	errors?: string[]
}

export interface SandboxResult {
	input: string
	type: SandboxInputType
	status: 'malicious' | 'suspicious' | 'clean' | 'unknown' | 'error'
	score: number
	providers: Partial<Record<ProviderKey, ProviderResult>>
	verdict?: string
	fileInfo?: {
		name: string
		size: number
		sha256?: string
		md5?: string
		sha1?: string
	}
}

export interface SandboxJobStage {
	stage: 'queued' | 'uploading' | 'analyzing' | 'completed' | 'failed'
	provider?: string
	progress?: number
}

declare global {
	interface Window {
		api: {
			getSettings: () => Promise<ApiKeys>
			saveSettings: (keys: ApiKeys) => Promise<{ ok: boolean }>
			getSandboxSettings: () => Promise<SandboxSettings>
			saveSandboxSettings: (settings: SandboxSettings) => Promise<{ ok: boolean }>
			scanIOCs: (payload: { iocs: string[]; providers: ProviderSelection; jobId: string }) => Promise<IocResult[]>
			scanSandbox: (payload: { 
				type: SandboxInputType; 
				input: string | { path: string; name: string; size: number }; 
				providers: SandboxProviderSelection; 
				settings: SandboxSettings;
				jobId: string 
			}) => Promise<SandboxResult>
			cancelScan: (jobId: string) => Promise<void>
			exportCsv: (csv: string) => Promise<{ canceled: boolean; filePath?: string }>
			exportSandboxJson: (result: SandboxResult) => Promise<{ canceled: boolean; filePath?: string }>
			copyToClipboard: (text: string) => Promise<void>
			pasteImageToText?: () => Promise<string>
			selectFile: () => Promise<{ canceled: boolean; filePath?: string; fileName?: string; fileSize?: number }>
			onScanProgress: (callback: (data: { jobId: string; iocIndex: number; provider: string; result: ProviderResult }) => void) => () => void
			onSandboxProgress: (callback: (data: { jobId: string; stage: SandboxJobStage; provider?: string; result?: ProviderResult }) => void) => () => void
			getRateLimits: () => Promise<Record<string, { remaining?: number; resetAt?: number; lastSeen?: number }>>
		}
	}
}

export {} 