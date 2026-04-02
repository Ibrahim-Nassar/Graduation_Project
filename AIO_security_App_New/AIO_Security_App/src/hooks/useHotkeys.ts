import { useEffect } from 'react'

type HotkeyBinding = { combo: string; handler: (e: KeyboardEvent) => void }

type KeyboardEventWithMeta = KeyboardEvent & { metaKey?: boolean }

export function useHotkeys(bindings: Array<HotkeyBinding>) {
	useEffect(() => {
		function onKey(e: KeyboardEventWithMeta){
			const parts: string[] = []
			if (e.ctrlKey) parts.push('ctrl')
			if (e.metaKey) parts.push('meta')
			if (e.shiftKey) parts.push('shift')
			if (e.altKey) parts.push('alt')
			const key = e.key.toLowerCase()
			if (!['control','shift','alt','meta'].includes(key)) parts.push(key)
			const combo = parts.join('+')
			for (const b of bindings){
				if (b.combo === combo){
					e.preventDefault()
					b.handler(e)
					break
				}
			}
		}
		document.addEventListener('keydown', onKey)
		return () => document.removeEventListener('keydown', onKey)
	}, [bindings])
} 