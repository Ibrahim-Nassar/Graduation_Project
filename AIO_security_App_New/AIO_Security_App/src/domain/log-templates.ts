import { IocContext } from './ioc-detection';

export interface LogTemplate {
    id: string;
    name: string;
    description: string;
    match: (line: string) => boolean;
    parse: (line: string) => Partial<IocContext>;
    example: string;
}

const IP_PATTERN = /(?:[0-9]{1,3}\.){3}[0-9]{1,3}/.source;
const DATE_PATTERN = /\d{4}-\d{2}-\d{2}/.source;
const TIME_PATTERN = /\d{2}:\d{2}:\d{2}/.source;

export const LOG_TEMPLATES: LogTemplate[] = [
    {
        id: 'generic-firewall',
        name: 'Generic Firewall',
        description: 'Date Time Action Protocol SrcIP DstIP SrcPort DstPort',
        example: '2023-10-27 10:15:30 ALLOW TCP 192.168.1.50 10.0.0.5 443 8080',
        match: (line) => /ALLOW|DENY|DROP|REJECT/.test(line) && /\d{4}-\d{2}-\d{2}/.test(line),
        parse: (line) => {
            const context: Partial<IocContext> = {};
            
            // Attempt to extract timestamp
            const tsMatch = line.match(new RegExp(`${DATE_PATTERN}[T\\s]${TIME_PATTERN}`));
            if (tsMatch) context.timestamp = tsMatch[0];

            // Attempt to find IPs
            const ips = line.match(new RegExp(IP_PATTERN, 'g'));
            if (ips && ips.length >= 2) {
                context.srcIp = ips[0];
                context.dstIp = ips[1];
            }

            // Attempt to find ports (simplified)
            const ports = line.match(/\b\d{1,5}\b/g)?.filter(p => {
                const n = parseInt(p, 10);
                return n > 0 && n <= 65535 && !p.includes('.'); // Not part of IP
            });
            // This port heuristic is weak, but usually ports follow IPs in FW logs
            // or are labeled. Without labels, it's a guess. 
            // Let's assume standard position if possible or just look for numbers around the IPs.
            // For this generic template, we'll rely on the user seeing the original line 
            // if strict parsing fails, but we'll try to grab what looks like ports.
             if (ports && ports.length >= 2) {
                 // Filter out the date parts if they matched \b\d{1,5}\b
                 const cleanPorts = ports.filter(p => !line.includes(p + '-') && !line.includes('-' + p) && !line.includes(':' + p));
                 if (cleanPorts.length >= 2) {
                     // context.srcPort = parseInt(cleanPorts[0], 10); // Dangerous assumption
                     // context.dstPort = parseInt(cleanPorts[1], 10);
                 }
             }

            return context;
        }
    },
    {
        id: 'generic-proxy',
        name: 'Generic HTTP Proxy',
        description: 'Date Time User SrcIP URL Status Bytes',
        example: '2023-10-27 10:15:30 bob.alice 192.168.1.50 https://example.com 200 1024',
        match: (line) => /http|https/.test(line) && /\d{3}\s+\d+/.test(line), // URL + Status/Bytes pattern
        parse: (line) => {
            const context: Partial<IocContext> = {};
            
            const tsMatch = line.match(new RegExp(`${DATE_PATTERN}[T\\s]${TIME_PATTERN}`));
            if (tsMatch) context.timestamp = tsMatch[0];

            const ips = line.match(new RegExp(IP_PATTERN, 'g'));
            if (ips && ips.length > 0) context.srcIp = ips[0];

            // Username often appears before IP or URL. Looks like email or name.
            // Heuristic: word chars, maybe dots, not http, not IP.
            const words = line.split(/\s+/);
            const userCandidate = words.find(w => 
                !w.includes(':') && 
                !w.match(/^\d+$/) && 
                !w.match(new RegExp(`^${IP_PATTERN}$`)) &&
                w.length > 2
            );
            if (userCandidate) context.username = userCandidate;

            return context;
        }
    },
    {
        id: 'generic-dns',
        name: 'Generic DNS Log',
        description: 'Date Time SrcIP QueryType Query Status',
        example: '2023-10-27 10:15:30 192.168.1.50 A example.com NOERROR',
        match: (line) => /\s(A|AAAA|CNAME|MX|TXT|PTR)\s/.test(line) || /NOERROR|NXDOMAIN|SERVFAIL/.test(line),
        parse: (line) => {
             const context: Partial<IocContext> = {};
            const tsMatch = line.match(new RegExp(`${DATE_PATTERN}[T\\s]${TIME_PATTERN}`));
            if (tsMatch) context.timestamp = tsMatch[0];
            
            const ips = line.match(new RegExp(IP_PATTERN, 'g'));
            if (ips && ips.length > 0) context.srcIp = ips[0];

            return context;
        }
    },
    {
        id: 'generic-edr',
        name: 'Generic EDR Alert',
        description: 'Date Time Hostname User Severity AlertName FileHash',
        example: '2023-10-27 10:15:30 workstation-01 bob.alice HIGH MaliciousFileDetected a1b2c3d4...',
        match: (line) => /HIGH|MEDIUM|LOW|CRITICAL/.test(line) && /[a-f0-9]{32,64}/i.test(line),
        parse: (line) => {
            const context: Partial<IocContext> = {};
            const tsMatch = line.match(new RegExp(`${DATE_PATTERN}[T\\s]${TIME_PATTERN}`));
            if (tsMatch) context.timestamp = tsMatch[0];
            
            const words = line.split(/\s+/);
            // Hostname often 3rd token?
            // This is very loose. 
            // Let's look for common username patterns or severity.
            
            const severity = words.find(w => ['HIGH', 'MEDIUM', 'LOW', 'CRITICAL'].includes(w.toUpperCase()));
            if (severity) context['severity'] = severity; // Add arbitrary field

            return context;
        }
    }
];

export function getTemplateById(id: string): LogTemplate | undefined {
    return LOG_TEMPLATES.find(t => t.id === id);
}

export function autoDetectTemplate(line: string): LogTemplate | undefined {
    return LOG_TEMPLATES.find(t => t.match(line));
}




