import React, { Component, ErrorInfo, ReactNode } from 'react'

interface Props {
	children: ReactNode
	fallback?: ReactNode
}

interface State {
	hasError: boolean
	error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
	constructor(props: Props) {
		super(props)
		this.state = { hasError: false, error: null }
	}

	static getDerivedStateFromError(error: Error): State {
		return { hasError: true, error }
	}

	componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
		console.error('ErrorBoundary caught an error:', error, errorInfo)
	}

	render(): ReactNode {
		if (this.state.hasError) {
			if (this.props.fallback) {
				return this.props.fallback
			}

			return (
				<div style={{
					display: 'flex',
					flexDirection: 'column',
					alignItems: 'center',
					justifyContent: 'center',
					height: '100vh',
					padding: '24px',
					textAlign: 'center'
				}}>
					<div className="card panel" style={{ maxWidth: '600px' }}>
						<div className="card-header">
							<h2 className="card-title" style={{ color: 'var(--danger)' }}>
								Something went wrong
							</h2>
						</div>
						<div style={{ padding: '24px' }}>
							<p style={{ marginBottom: '16px', color: 'var(--text-secondary)' }}>
								An unexpected error occurred. Please try refreshing the page.
							</p>
							{this.state.error && (
								<details style={{ 
									marginTop: '16px', 
									padding: '12px', 
									background: 'var(--surface-secondary)', 
									borderRadius: '8px',
									textAlign: 'left'
								}}>
									<summary style={{ cursor: 'pointer', fontWeight: 600 }}>
										Error Details
									</summary>
									<pre style={{ 
										marginTop: '12px', 
										fontSize: '12px', 
										overflow: 'auto',
										maxHeight: '200px'
									}}>
										{this.state.error.toString()}
										{this.state.error.stack && `\n\n${this.state.error.stack}`}
									</pre>
								</details>
							)}
							<button 
								className="button primary" 
								onClick={() => window.location.reload()}
								style={{ marginTop: '24px' }}
							>
								Reload Application
							</button>
						</div>
					</div>
				</div>
			)
		}

		return this.props.children
	}
}

