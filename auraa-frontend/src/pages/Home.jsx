import React from 'react';
import { ContainerScroll } from '../components/ui/ContainerScrollAnimation';
import InteractiveTerminal from '../components/ui/InteractiveTerminal';
import { Shield, Zap, Globe, Database, Terminal, Lock, Server, FileCode, Activity, CheckCircle, FolderOpen, Sliders, FileJson } from 'lucide-react';
import Spotlight from '../components/ui/Spotlight';

const features = [
    { title: 'Typosquatting', description: 'Analyzes domain variations for phishing/spoofing risks.', icon: Globe, color: 'text-cyan-500' },
    { title: 'SQL Injection', description: 'Detects unauthorized database access attempts via URL parameters.', icon: Database, color: 'text-blue-500' },
    { title: 'XSS Detection', description: 'Identifies reflected and stored cross-site scripting vectors.', icon: Zap, color: 'text-yellow-500' },
    { title: 'Directory Traversal', description: 'Flags attempts to access unauthorized file system paths.', icon: FolderOpen, color: 'text-orange-500' },
    { title: 'Command Injection', description: 'Identifies OS command execution payloads in vectors.', icon: Terminal, color: 'text-red-500' },
    { title: 'SSRF', description: 'Detects server-side request forgery attempts to internal services.', icon: Server, color: 'text-purple-500' },
    { title: 'LFI / RFI', description: 'Monitors for local and remote file inclusion patterns.', icon: FileCode, color: 'text-pink-500' },
    { title: 'Credential Stuffing', description: 'Correlates high-frequency login attempts and failures.', icon: Shield, color: 'text-emerald-500' },
    { title: 'HTTP Param Pollution', description: 'Detects duplicate parameters used to bypass WAF rules.', icon: Sliders, color: 'text-indigo-500' },
    { title: 'XXE Injection', description: 'Flags XML external entity processing attempts.', icon: FileJson, color: 'text-rose-500' },
    { title: 'Web Shells', description: 'Identifies backdoor upload attempts (jsp, php, asp).', icon: Lock, color: 'text-teal-500' },
];

export default function Home() {
    return (
        <div className="flex flex-col overflow-hidden selection:bg-blue-500/30">
            {/* Hero Section */}
            <ContainerScroll
                titleComponent={
                    <>
                        <h1 className="text-4xl md:text-8xl font-bold text-white mb-4 tracking-tighter">
                            Silence the Noise. <br />
                            <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-cyan-400">
                                Confirm the Breach.
                            </span>
                        </h1>
                        <p className="text-gray-400 text-xl max-w-2xl mx-auto mb-8">
                            Next-Gen IPDR & PCAP Forensics. AURA prioritizes genuine compromises over blocked attempts using Response Analysis Rules.
                        </p>
                    </>
                }
            >
                <InteractiveTerminal />
            </ContainerScroll>

            {/* Logic Flow Section */}
            <div className="max-w-7xl mx-auto px-6 py-20 border-t border-white/10">
                <h2 className="text-3xl font-bold text-white mb-12 text-center">Operational Logic</h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
                    {/* Connecting Line (Desktop) */}
                    <div className="hidden md:block absolute top-1/2 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-500/0 via-blue-500/50 to-blue-500/0 -translate-y-1/2 z-0" />

                    <div className="relative z-10 bg-black border border-white/10 p-8 rounded-2xl text-center group hover:border-blue-500/50 transition-colors">
                        <div className="w-16 h-16 bg-blue-900/20 rounded-full flex items-center justify-center mx-auto mb-6 border border-blue-500/30 group-hover:scale-110 transition-transform">
                            <Activity className="w-8 h-8 text-blue-400" />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">1. Collect Data</h3>
                        <p className="text-gray-400 text-sm">Real-time IPDR/PCAP Stream ingestion and parsing.</p>
                    </div>

                    <div className="relative z-10 bg-black border border-white/10 p-8 rounded-2xl text-center group hover:border-purple-500/50 transition-colors">
                        <div className="w-16 h-16 bg-purple-900/20 rounded-full flex items-center justify-center mx-auto mb-6 border border-purple-500/30 group-hover:scale-110 transition-transform">
                            <Server className="w-8 h-8 text-purple-400" />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">2. Analyze</h3>
                        <p className="text-gray-400 text-sm">Correlation of Request + Response Size + Status Code.</p>
                    </div>

                    <div className="relative z-10 bg-black border border-white/10 p-8 rounded-2xl text-center group hover:border-red-500/50 transition-colors">
                        <div className="w-16 h-16 bg-red-900/20 rounded-full flex items-center justify-center mx-auto mb-6 border border-red-500/30 group-hover:scale-110 transition-transform">
                            <CheckCircle className="w-8 h-8 text-red-400" />
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">3. Final Decision</h3>
                        <p className="text-gray-400 text-sm">Distinguish "Attempt" vs "Successful Breach".</p>
                    </div>
                </div>
            </div>

            {/* Bento Grid Features */}
            <div className="max-w-7xl mx-auto px-6 pb-32">
                <h2 className="text-3xl font-bold text-white mb-12 text-center">Monitored Threats</h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {features.map((feature, idx) => (
                        <Spotlight key={idx} className="p-8 h-64 flex flex-col justify-between group border-white/5 bg-white/5 hover:bg-white/10">
                            <feature.icon className={`w-10 h-10 ${feature.color} mb-4 group-hover:scale-110 transition-transform`} />
                            <div>
                                <h3 className="text-lg font-bold text-white mb-2">{feature.title}</h3>
                                <p className="text-gray-400 text-sm leading-snug">{feature.description}</p>
                            </div>
                        </Spotlight>
                    ))}
                </div>
            </div>
        </div>
    );
}
