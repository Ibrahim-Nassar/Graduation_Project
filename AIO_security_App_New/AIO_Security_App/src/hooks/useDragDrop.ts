import { useState, useCallback } from 'react'

interface UseDragDropOptions {
	onDrop: (file: File) => void | Promise<void>
	acceptedTypes?: string[]
}

interface UseDragDropReturn {
	isDragOver: boolean
	handleDragOver: (e: React.DragEvent) => void
	handleDragLeave: (e: React.DragEvent) => void
	handleDrop: (e: React.DragEvent) => void
}

/**
 * Custom hook for handling file drag and drop operations
 * @param options Configuration options
 * @returns Drag and drop handlers and state
 */
export function useDragDrop({ onDrop, acceptedTypes }: UseDragDropOptions): UseDragDropReturn {
	const [isDragOver, setIsDragOver] = useState(false)

	const handleDragOver = useCallback((e: React.DragEvent) => {
		e.preventDefault()
		setIsDragOver(true)
	}, [])

	const handleDragLeave = useCallback((e: React.DragEvent) => {
		e.preventDefault()
		setIsDragOver(false)
	}, [])

	const handleDrop = useCallback((e: React.DragEvent) => {
		e.preventDefault()
		setIsDragOver(false)
		
		const files = Array.from(e.dataTransfer.files)
		if (files.length === 0) return

		const file = files[0]
		if (!file) return

		// Check file type if acceptedTypes is provided
		if (acceptedTypes && acceptedTypes.length > 0) {
			const extension = file.name.split('.').pop()?.toLowerCase()
			if (extension && !acceptedTypes.includes(extension)) {
				console.warn(`File type .${extension} not accepted`)
				return
			}
		}

		void onDrop(file)
	}, [onDrop, acceptedTypes])

	return {
		isDragOver,
		handleDragOver,
		handleDragLeave,
		handleDrop
	}
}

