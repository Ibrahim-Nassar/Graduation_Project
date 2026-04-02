import React from 'react';
import { CaseIoc, IocHistoryEntry } from '../types/case';
import { ProviderResult } from '../types/providers';

interface IocDetailPanelProps {
    ioc: CaseIoc | null;
    history?: IocHistoryEntry[];
    onClose: () => void;
}

export default function IocDetailPanel({ ioc, history, onClose }: IocDetailPanelProps) {
    if (!ioc) return null;

    return (
        <div style={{
            position: 'fixed',
            top: 0,
            right: 0,
            bottom: 0,
            width: '500px',
            background: 'var(--surface-primary)',
            borderLeft: '1px solid var(--border-primary)',
            boxShadow: '-4px 0 20px rgba(0,0,0,0.2)',
            display: 'flex',
            flexDirection: 'column',
            zIndex: 100
        }}>
            {/* Header */}
            <div style={{
                padding: '20px',
                borderBottom: '1px solid var(--border-primary)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                background: 'var(--surface-secondary)'
            }}>
                <div>
                    <div style={{ fontSize: '12px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        {ioc.type}
                    </div>
                    <div style={{ fontSize: '18px', fontWeight: 600, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                        {ioc.ioc}
                    </div>
                </div>
                <button onClick={onClose} style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-secondary)',
                    fontSize: '24px',
                    cursor: 'pointer',
                    padding: '0 8px'
                }}>×</button>
            </div>

            {/* Content */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>
                
                {/* Status Summary */}
                <div style={{ marginBottom: '24px' }}>
                    <div style={{ 
                        display: 'inline-flex', 
                        alignItems: 'center', 
                        padding: '8px 16px', 
                        borderRadius: '6px', 
                        fontWeight: 600,
                        fontSize: '14px',
                        background: ioc.status === 'malicious' ? 'rgba(239, 68, 68, 0.1)' : 
                                    ioc.status === 'suspicious' ? 'rgba(245, 158, 11, 0.1)' : 
                                    ioc.status === 'clean' ? 'rgba(16, 185, 129, 0.1)' : 'var(--surface-secondary)',
                        color: ioc.status === 'malicious' ? '#ef4444' : 
                               ioc.status === 'suspicious' ? '#f59e0b' : 
                               ioc.status === 'clean' ? '#10b981' : 'var(--text-secondary)'
                    }}>
                        Status: {ioc.status.toUpperCase()}
                        {ioc.score > 0 && <span style={{ marginLeft: '8px', opacity: 0.8 }}>| Score: {ioc.score}</span>}
                    </div>
                </div>

                {/* Context Section */}
                <div className="detail-section" style={{ marginBottom: '24px' }}>
                    <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '12px' }}>
                        Context
                    </h3>
                    <div style={{ background: 'var(--surface-secondary)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border-primary)' }}>
                        {ioc.context?.timestamp && (
                            <div style={{ marginBottom: '8px', fontSize: '13px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Timestamp: </span>
                                <span style={{ fontFamily: 'monospace' }}>{ioc.context.timestamp}</span>
                            </div>
                        )}
                         {ioc.context?.srcIp && (
                            <div style={{ marginBottom: '8px', fontSize: '13px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Src IP: </span>
                                <span style={{ fontFamily: 'monospace' }}>{ioc.context.srcIp}</span>
                            </div>
                        )}
                        {ioc.context?.dstIp && (
                            <div style={{ marginBottom: '8px', fontSize: '13px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>Dst IP: </span>
                                <span style={{ fontFamily: 'monospace' }}>{ioc.context.dstIp}</span>
                            </div>
                        )}
                         {ioc.context?.username && (
                            <div style={{ marginBottom: '8px', fontSize: '13px' }}>
                                <span style={{ color: 'var(--text-secondary)' }}>User: </span>
                                <span>{ioc.context.username}</span>
                            </div>
                        )}
                        {ioc.context?.sourceLine && (
                            <div style={{ marginTop: '12px' }}>
                                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '4px' }}>Original Source:</div>
                                <pre style={{ 
                                    margin: 0, 
                                    whiteSpace: 'pre-wrap', 
                                    wordBreak: 'break-all', 
                                    fontSize: '11px', 
                                    background: '#000', 
                                    padding: '8px', 
                                    borderRadius: '4px',
                                    color: '#ccc'
                                }}>
                                    {ioc.context.sourceLine}
                                </pre>
                            </div>
                        )}
                    </div>
                </div>

                {/* Providers Section */}
                <div className="detail-section" style={{ marginBottom: '24px' }}>
                    <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '12px' }}>
                        Threat Intelligence
                    </h3>
                    <div style={{ display: 'grid', gap: '12px' }}>
                        {Object.entries(ioc.providers || {}).map(([name, result]) => {
                            if (!result) return null;
                            const res = result as ProviderResult;
                            return (
                                <div key={name} style={{ 
                                    border: '1px solid var(--border-primary)', 
                                    borderRadius: '6px',
                                    overflow: 'hidden'
                                }}>
                                    <div style={{ 
                                        padding: '10px 12px', 
                                        background: 'var(--surface-secondary)',
                                        display: 'flex',
                                        justifyContent: 'space-between',
                                        alignItems: 'center'
                                    }}>
                                        <div style={{ fontWeight: 500 }}>{name}</div>
                                        <div style={{ fontSize: '12px' }}>
                                             <span className={`badge ${res.status || 'unknown'}`} style={{ transform: 'scale(0.9)' }}>{res.status}</span>
                                        </div>
                                    </div>
                                    <div style={{ padding: '12px' }}>
                                        {/* Specific provider fields could be rendered here */}
                                        {res.details && (
                                            <pre style={{ 
                                                margin: 0, 
                                                fontSize: '11px', 
                                                maxHeight: '150px', 
                                                overflowY: 'auto',
                                                color: 'var(--text-secondary)'
                                            }}>
                                                {JSON.stringify(res.details, null, 2)}
                                            </pre>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                 {/* History Section */}
                 {history && history.length > 0 && (
                    <div className="detail-section">
                        <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '12px' }}>
                            Case History
                        </h3>
                         <div style={{ display: 'grid', gap: '8px' }}>
                            {history.map((entry, i) => (
                                <div key={i} style={{ 
                                    padding: '10px', 
                                    background: 'var(--surface-secondary)', 
                                    borderRadius: '6px',
                                    fontSize: '13px',
                                    display: 'flex',
                                    justifyContent: 'space-between'
                                }}>
                                    <div>
                                        <div style={{ fontWeight: 500 }}>{entry.caseName}</div>
                                        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                                            {new Date(entry.timestamp).toLocaleDateString()}
                                        </div>
                                    </div>
                                    <div className={`status-indicator ${entry.status}`} />
                                </div>
                            ))}
                        </div>
                    </div>
                )}

            </div>
        </div>
    );
}




