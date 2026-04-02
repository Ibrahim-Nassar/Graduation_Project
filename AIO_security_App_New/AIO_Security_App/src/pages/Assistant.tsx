import React from 'react'

export default function Assistant(){
	return (
		<div className="card panel" style={{width:'min(900px, 100%)', margin:'0 auto'}}>
			<div style={{display:'grid', gap:8}}>
				<div className="label">Assistant</div>
				<div className="hint">This is a placeholder for a future assistant panel.</div>
				<div style={{height:220, border:'1px dashed var(--border)', borderRadius:10}}/>
			</div>
		</div>
	)
} 