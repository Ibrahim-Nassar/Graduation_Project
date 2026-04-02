import React, { createContext, useContext, useState, useCallback, ReactNode, useEffect } from 'react'

export interface Toast {
	id: string
	kind: 'success' | 'error' | 'info'
	title: string
	message?: string
	isRemoving?: boolean
}

interface ToastContextType {
	push: (toast: Omit<Toast, 'id'>) => void
}

const ToastCtx = createContext<ToastContextType | null>(null)

export function ToastProvider({ children }: { children: ReactNode }) {
	const [toasts, setToasts] = useState<Toast[]>([])

	const push = useCallback((toast: Omit<Toast, 'id'>) => {
		const id = Math.random().toString(36).slice(2)
		const newToast = { ...toast, id, isRemoving: false }
		
		setToasts(prev => [...prev, newToast])
		
		// Start removal animation after 3.5 seconds
		setTimeout(() => {
			setToasts(prev => prev.map(t => t.id === id ? { ...t, isRemoving: true } : t))
		}, 3500)
		
		// Actually remove after animation completes
		setTimeout(() => {
			setToasts(prev => prev.filter(t => t.id !== id))
		}, 4000)
	}, [])

	const remove = useCallback((id: string) => {
		// Start removal animation immediately
		setToasts(prev => prev.map(t => t.id === id ? { ...t, isRemoving: true } : t))
		
		// Actually remove after animation completes
		setTimeout(() => {
			setToasts(prev => prev.filter(t => t.id !== id))
		}, 300)
	}, [])

	return (
		<ToastCtx.Provider value={{ push }}>
			{children}
			<div className="toast-center">
				{toasts.map(toast => (
					<div 
						key={toast.id} 
						className={`toast ${toast.kind} ${toast.isRemoving ? 'removing' : ''}`}
						onClick={() => remove(toast.id)}
						style={{ cursor: 'pointer' }}
					>
						<div className="title">{toast.title}</div>
						{toast.message && <div className="message">{toast.message}</div>}
					</div>
				))}
			</div>
		</ToastCtx.Provider>
	)
}

export function useToast() {
	const ctx = useContext(ToastCtx)
	if (!ctx) throw new Error('ToastProvider missing')
	return ctx
} 