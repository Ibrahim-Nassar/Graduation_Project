import { describe, it, expect } from 'vitest';
import { LOG_TEMPLATES, getTemplateById } from '../domain/log-templates';
import { extractIOCsWithContext } from '../domain/ioc-detection';

describe('Log Templates Parsing', () => {
    
    it('should parse Generic Firewall logs', () => {
        const template = getTemplateById('generic-firewall');
        expect(template).toBeDefined();
        
        const logLine = '2023-10-27 10:15:30 ALLOW TCP 192.168.1.50 10.0.0.5 443 8080';
        const context = template!.parse(logLine);
        
        expect(context.timestamp).toContain('2023-10-27');
        expect(context.srcIp).toBe('192.168.1.50');
        expect(context.dstIp).toBe('10.0.0.5');
    });

    it('should parse Generic Proxy logs', () => {
        const template = getTemplateById('generic-proxy');
        expect(template).toBeDefined();

        const logLine = '2023-10-27 10:15:30 bob.alice 192.168.1.50 https://example.com 200 1024';
        const context = template!.parse(logLine);

        expect(context.timestamp).toContain('2023-10-27');
        expect(context.srcIp).toBe('192.168.1.50');
        expect(context.username).toBe('bob.alice');
    });

    it('should parse Generic DNS logs', () => {
        const template = getTemplateById('generic-dns');
        const logLine = '2023-10-27 10:15:30 192.168.1.50 A example.com NOERROR';
        const context = template!.parse(logLine);

        expect(context.timestamp).toContain('2023-10-27');
        expect(context.srcIp).toBe('192.168.1.50');
    });

    it('should extract IOCs with context using specific template', () => {
        const template = getTemplateById('generic-firewall');
        const logLine = '2023-10-27 10:15:30 ALLOW TCP 192.168.1.50 10.0.0.5';
        
        const results = extractIOCsWithContext(logLine, (line) => template!.parse(line));
        
        expect(results.length).toBeGreaterThan(0);
        const ipRes = results.find(r => r.value === '192.168.1.50');
        expect(ipRes).toBeDefined();
        expect(ipRes!.context.srcIp).toBe('192.168.1.50');
        expect(ipRes!.context.dstIp).toBe('10.0.0.5');
        expect(ipRes!.context.timestamp).toBeDefined();
    });

    it('should handle lines that do not match well gracefully', () => {
        const template = getTemplateById('generic-firewall');
        const logLine = 'Invalid Line Here';
        const context = template!.parse(logLine);
        
        // Should just return empty or minimal context without crashing
        expect(context).toEqual({});
    });
});




