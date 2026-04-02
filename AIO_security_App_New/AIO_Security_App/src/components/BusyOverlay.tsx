import React from 'react'

export default function BusyOverlay({ visible, text }:{ visible: boolean; text?: string }){
	if (!visible) return null
	return (
		<div className="overlay">
			<div style={{display:'grid',gap:12,placeItems:'center'}}>
				<div className="spinner"/>
				{Boolean(text) && <div className="hint">{text}</div>}
			</div>
		</div>
	)
} 