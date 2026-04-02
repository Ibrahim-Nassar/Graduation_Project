import React from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import Checker from './pages/Checker'
import Assistant from './pages/Assistant'
import Settings from './pages/Settings'
import Sandbox from './pages/Sandbox'
import Help from './pages/Help'
import { ToastProvider } from './context/ToastContext'
import { ErrorBoundary } from './components/ErrorBoundary'

export default function App(){
	return (
		<ErrorBoundary>
			<ToastProvider>
			<div className="topbar">
				<div className="brand">
					<div className="icon"></div>
					<span>IOC Checker</span>
				</div>
				<nav className="tabs">
					<NavLink to="/" className={({isActive}) => isActive ? 'tab active' : 'tab'}>
						Checker
					</NavLink>
					<NavLink to="/assistant" className={({isActive}) => isActive ? 'tab active' : 'tab'}>
						Assistant
					</NavLink>
					<NavLink to="/settings" className={({isActive}) => isActive ? 'tab active' : 'tab'}>
						Settings
					</NavLink>
					<NavLink to="/help" className={({isActive}) => isActive ? 'tab active' : 'tab'}>
						Help
					</NavLink>
					<NavLink to="/sandbox" className={({isActive}) => isActive ? 'tab active' : 'tab'}>
						Sandbox
					</NavLink>
				</nav>
			</div>
			<main>
				<Routes>
					<Route path="/" element={<Checker/>} />
					<Route path="/assistant" element={<Assistant/>} />
					<Route path="/settings" element={<Settings/>} />
					<Route path="/help" element={<Help/>} />
					<Route path="/sandbox" element={<Sandbox/>} />
				</Routes>
			</main>
			</ToastProvider>
		</ErrorBoundary>
	)
} 