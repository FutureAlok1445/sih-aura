import React, { useState } from 'react';
import { Book, FileText, Code, Terminal } from 'lucide-react';
import { cn } from '../lib/utils';

const topics = [
    { id: 'getting-started', title: 'Getting Started', icon: Book },
    { id: 'pcap-ingestion', title: 'PCAP Ingestion', icon: FileText },
    { id: 'detection-rules', title: 'Detection Rules', icon: Code },
    { id: 'api-reference', title: 'API Reference', icon: Terminal },
];

export default function Docs({ defaultTopic = 'getting-started' }) {
    const [activeTopic, setActiveTopic] = useState(defaultTopic);

    return (
        <div className="pt-24 px-6 pb-20 max-w-7xl mx-auto flex gap-12 min-h-screen">
            {/* Sidebar */}
            <div className="w-64 flex-shrink-0 hidden md:block">
                <div className="sticky top-32 space-y-2">
                    <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-4 px-3">Documentation</h3>
                    {topics.map((topic) => (
                        <button
                            key={topic.id}
                            onClick={() => setActiveTopic(topic.id)}
                            className={cn(
                                "w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors text-left",
                                activeTopic === topic.id
                                    ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                                    : "text-gray-400 hover:text-white hover:bg-white/5"
                            )}
                        >
                            <topic.icon className="w-4 h-4" />
                            {topic.title}
                        </button>
                    ))}
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 max-w-3xl">
                {activeTopic === 'getting-started' && (
                    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <h1 className="text-4xl font-bold text-white mb-4">Getting Started with AURA</h1>
                        <p className="text-gray-400 text-lg leading-relaxed">
                            AURA (Advanced URL Response Analyzer) is a next-generation forensic tool designed to distinguish between
                            attempted attacks and confirmed breaches. By correlating IPDR data with HTTP response sizes and status codes,
                            AURA eliminates false positives and focuses on operational intelligence.
                        </p>
                        <div className="p-6 bg-zinc-900 border border-white/10 rounded-xl">
                            <h3 className="text-white font-bold mb-2">Quick Start</h3>
                            <ol className="list-decimal list-inside text-gray-400 space-y-2">
                                <li>Navigate to the <span className="text-blue-400">Scanner Interface</span>.</li>
                                <li>Upload a .pcap file (Live URL scanning is deprecated).</li>
                                <li>Click "Initialize System" to begin analysis.</li>
                                <li>Review confirmed breaches in the Dashboard.</li>
                            </ol>
                        </div>
                    </div>
                )}

                {activeTopic === 'pcap-ingestion' && (
                    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <h1 className="text-4xl font-bold text-white mb-4">PCAP Ingestion</h1>
                        <p className="text-gray-400 text-lg leading-relaxed">
                            AURA supports standard PCAP and PCAPNG file formats. The ingestion engine parses HTTP streams to extract
                            URL parameters, headers, and payload bodies for analysis.
                        </p>
                        <h3 className="text-2xl font-bold text-white mt-8">Supported Formats</h3>
                        <ul className="list-disc list-inside text-gray-400 space-y-2">
                            <li>tcpdump capture files (.pcap)</li>
                            <li>Wireshark capture files (.pcapng)</li>
                            <li>Raw HTTP logs (.log)</li>
                        </ul>
                    </div>
                )}

                {activeTopic === 'detection-rules' && (
                    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <h1 className="text-4xl font-bold text-white mb-4">Response Analysis Rules</h1>
                        <p className="text-gray-400 text-lg leading-relaxed">
                            Traditional WAFs block based on request signatures. AURA validates the impact of the request by analyzing the server's response.
                        </p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
                            <div className="p-6 bg-red-900/10 border border-red-500/20 rounded-xl">
                                <h3 className="text-red-400 font-bold mb-2">Confirmed Breach</h3>
                                <p className="text-gray-400 text-sm">
                                    Attack Payload + 200 OK + Large Response Size.
                                    <br />
                                    Indicates the server processed the malicious input and returned data.
                                </p>
                            </div>
                            <div className="p-6 bg-green-900/10 border border-green-500/20 rounded-xl">
                                <h3 className="text-green-400 font-bold mb-2">Mitigated Attempt</h3>
                                <p className="text-gray-400 text-sm">
                                    Attack Payload + 403 Forbidden / 406 Not Acceptable.
                                    <br />
                                    Indicates the firewall or server blocked the request.
                                </p>
                            </div>
                        </div>
                    </div>
                )}

                {activeTopic === 'api-reference' && (
                    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <h1 className="text-4xl font-bold text-white mb-4">API Reference</h1>
                        <p className="text-gray-400 text-lg leading-relaxed">
                            Automate your threat hunting with the AURA API.
                        </p>
                        <div className="bg-black border border-white/10 rounded-xl p-4 font-mono text-sm overflow-x-auto">
                            <p className="text-gray-500 mb-2">// POST /api/v1/scan</p>
                            <div className="text-blue-400">
                                {`{
  "target": "https://example.com",
  "mode": "deep_scan",
  "rules": ["sqli", "xss", "rce"]
}`}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}
