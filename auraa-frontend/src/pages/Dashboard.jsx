import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
    Shield, 
    AlertTriangle, 
    Activity, 
    Server, 
    Lock, 
    CheckCircle, 
    X 
} from 'lucide-react';
import StatCard from '../components/StatCard';
import ThreatDonut from '../components/ThreatDonut';
import AttackMap from '../components/AttackMap';
import ThreatLogTable from '../components/ThreatLogTable';
import AttackExplanation from "../components/AttackExplanation";
import AttackTypeSummary from "../components/AttackTypeSummary";

// Simple Toast Notification Component
const Toast = ({ message, onClose }) => {
    if (!message) return null;
    return (
        <div className="fixed bottom-6 right-6 z-50 animate-in slide-in-from-bottom-5 fade-in duration-300">
            <div className="bg-blue-600 text-white px-4 py-3 rounded-lg shadow-2xl flex items-center gap-3 border border-blue-400/50 backdrop-blur-md">
                <div className="bg-white/20 p-1.5 rounded-full">
                    <CheckCircle className="w-5 h-5 text-white" />
                </div>
                <div>
                    <h4 className="font-semibold text-sm">Analysis Update</h4>
                    <p className="text-xs text-blue-100">{message}</p>
                </div>
                <button onClick={onClose} className="ml-2 hover:bg-white/10 p-1 rounded transition-colors">
                    <X className="w-4 h-4" />
                </button>
            </div>
        </div>
    );
};

export default function Dashboard() {
    const [traffic, setTraffic] = useState([]);
    const [searchTerm, setSearchTerm] = useState("");
    const [severityFilter, setSeverityFilter] = useState("All");
    const [mapData, setMapData] = useState([]);
    const [backendStats, setBackendStats] = useState(null);
    const [loadError, setLoadError] = useState(null);

    // --- XAI State ---
    const [selectedAttack, setSelectedAttack] = useState(null); 

    // Toast State
    const [toastMsg, setToastMsg] = useState(null);

    // Refs to track state without triggering re-renders inside the poll loop
    const notifiedLayers = useRef(new Set());
    const isFirstLoad = useRef(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [attacksRes, statsRes, trafficRes] = await Promise.all([
                    fetch('http://127.0.0.1:8000/api/attacks/'),
                    fetch('http://127.0.0.1:8000/api/stats/'),
                    fetch('http://127.0.0.1:8000/api/traffic/'),
                ]);

                if (attacksRes.ok && statsRes.ok && trafficRes.ok) {
                    const [attacksData, statsData, trafficData] = await Promise.all([
                        attacksRes.json(),
                        statsRes.json(),
                        trafficRes.json(),
                    ]);

                    setTraffic(attacksData || []);
                    setBackendStats(statsData || null);
                    setMapData(trafficData || []);
                    setLoadError(null);

                    // --- NEW LAYER DETECTION LOGIC ---
                    const currentMethods = new Set();
                    (attacksData || []).forEach(row => {
                        if (row.evidence && row.evidence !== "No threat detected") {
                            if (row.evidence.includes("Regex")) currentMethods.add("Regex");
                            else if (row.evidence.includes("ML")) currentMethods.add("ML");
                            else if (row.evidence.includes("Spoofing")) currentMethods.add("Spoofing");
                            else if (row.evidence.includes("AI")) currentMethods.add("AI");
                            
                            if (row.detection_method) currentMethods.add(row.detection_method);
                        }
                    });

                    // Check for NEW layers
                    const layersToCheck = [
                        { id: "Regex", label: "Regex Pattern Matching Complete" },
                        { id: "ML", label: "Machine Learning Analysis Loaded" },
                        { id: "Spoofing", label: "URL Spoofing Checks Loaded" },
                        { id: "AI", label: "Advanced BERT Model Results Loaded" }
                    ];

                    layersToCheck.forEach(layer => {
                        if (currentMethods.has(layer.id) && !notifiedLayers.current.has(layer.id)) {
                            notifiedLayers.current.add(layer.id);
                            
                            if (!isFirstLoad.current) {
                                setToastMsg(layer.label);
                                setTimeout(() => setToastMsg(null), 4000);
                            }
                        }
                    });

                    isFirstLoad.current = false;
                }
            } catch (err) {
                console.error('Failed to load dashboard data', err);
            }
        };

        fetchData();
        const intervalId = setInterval(fetchData, 10000);
        return () => clearInterval(intervalId);
    }, []);

    // ... Filter Logic ...
    const filteredTraffic = useMemo(() => {
        let data = traffic;
        if (severityFilter !== "All") {
            const filterLower = severityFilter.toLowerCase();
            data = data.filter(t => (t.severity || "").toLowerCase() === filterLower);
        }
        if (searchTerm) {
            const lowerTerm = searchTerm.toLowerCase();
            data = data.filter(t =>
                (t.type && t.type.toLowerCase().includes(lowerTerm)) ||
                (t.ip && t.ip.includes(lowerTerm)) ||
                (t.status && t.status.toLowerCase().includes(lowerTerm)) ||
                (t.result && t.result.toLowerCase().includes(lowerTerm))
            );
        }
        return data;
    }, [traffic, searchTerm, severityFilter]);

    // ... Stats Logic ...
    const stats = useMemo(() => {
        if (backendStats && typeof backendStats.total !== 'undefined') return backendStats;
        const dataToUse = traffic || [];
        const total = dataToUse.length;
        const threats = dataToUse.filter(t => t.type !== 'Benign').length;
        const breachTypes = new Set(["Command Injection","SSRF","Directory Traversal / LFI","Remote File Inclusion (RFI)","Shell Upload Attempt","Bruteforce Attack"]);
        const breaches = dataToUse.filter(t => {
            let statusCode = 0;
            if (typeof t.status_code === 'number') statusCode = t.status_code;
            else if (typeof t.status_code === 'string') statusCode = parseInt(t.status_code, 10) || 0;
            return breachTypes.has(t.type) && statusCode >= 200 && statusCode < 300;
        }).length;
        let health = 100;
        if (total > 0) {
            const risk = Math.min(100, Math.trunc((threats / total) * 100));
            health = Math.max(0, 100 - risk);
        }
        return { total, threats, breaches, health, breakdown: {} };
    }, [traffic, backendStats]);

    return (
        <div className="p-6 space-y-6 pt-24 min-h-screen relative">
            {/* TOAST NOTIFICATION */}
            <Toast message={toastMsg} onClose={() => setToastMsg(null)} />

            {loadError && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-red-200 text-sm">
                    {loadError}
                </div>
            )}

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard title="Total Events" value={stats.total.toLocaleString()} icon={Activity} trend={searchTerm ? "Filtered" : "+0%"} color="text-blue-500" />
                <StatCard title="Threats Detected" value={stats.threats.toLocaleString()} icon={AlertTriangle} trend={searchTerm ? "Filtered" : "+0%"} color="text-yellow-500" />
                <StatCard title="Active Breaches" value={stats.breaches.toLocaleString()} icon={Lock} trend={stats.breaches > 0 ? "CRITICAL" : "SECURE"} color="text-red-500" className={stats.breaches > 0 ? "animate-pulse border-red-500/50" : ""} />
                <StatCard title="System Health" value={`${stats.health}%`} icon={Server} trend="Stable" color="text-green-500" />
            </div>

            {/* Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                    <AttackMap data={mapData} />
                </div>
                <div>
                    <ThreatDonut data={filteredTraffic} />
                </div>
            </div>

            {/* Table Section */}
            <div className="bg-black/40 border border-white/10 rounded-xl overflow-hidden backdrop-blur-sm">
                <ThreatLogTable
                    attacks={filteredTraffic}
                    onSearch={setSearchTerm}
                    selectedSeverity={severityFilter}
                    onSeverityChange={setSeverityFilter}
                    onSelectAttack={setSelectedAttack} // <--- Pass handler to Table
                />
            </div>

            {/* --- XAI & SUMMARY SECTIONS --- */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Per-event BERT explanation */}
                <div className="lg:col-span-2">
                    <AttackExplanation selectedAttack={selectedAttack} />
                </div>
                
                {/* Global Summary */}
                <div>
                    <AttackTypeSummary attacks={traffic} />
                </div>
            </div>
        </div>
    );
}