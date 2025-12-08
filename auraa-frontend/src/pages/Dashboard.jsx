import React, { useState, useEffect, useMemo } from 'react';
import { Shield, AlertTriangle, Activity, Server, Lock } from 'lucide-react';
import StatCard from '../components/StatCard';
import ThreatDonut from '../components/ThreatDonut';
import AttackMap from '../components/AttackMap';
import ThreatLogTable from '../components/ThreatLogTable';

export default function Dashboard() {
    const [traffic, setTraffic] = useState([]);
    const [searchTerm, setSearchTerm] = useState("");
    const [severityFilter, setSeverityFilter] = useState("All");

    const [mapData, setMapData] = useState([]);
    const [backendStats, setBackendStats] = useState(null);
    const [loadError, setLoadError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [attacksRes, statsRes, trafficRes] = await Promise.all([
                    fetch('http://127.0.0.1:8000/api/attacks/'),
                    fetch('http://127.0.0.1:8000/api/stats/'),
                    fetch('http://127.0.0.1:8000/api/traffic/'),
                ]);

                const [attacksData, statsData, trafficData] = await Promise.all([
                    attacksRes.json(),
                    statsRes.json(),
                    trafficRes.json(),
                ]);

                setTraffic(attacksData || []);
                setBackendStats(statsData || null);
                setMapData(trafficData || []);
                setLoadError(null);
            } catch (err) {
                console.error('Failed to load dashboard data', err);
                setLoadError('Could not load dashboard data.');
            }
        };

        fetchData();
    }, []);

    // Filter Logic
    const filteredTraffic = useMemo(() => {
        let data = traffic;

        // 1. Severity Filter
        if (severityFilter !== "All") {
            data = data.filter(t => t.severity === severityFilter);
        }

        // 2. Search Filter
        if (searchTerm) {
            const lowerTerm = searchTerm.toLowerCase();
            data = data.filter(t =>
                (t.type && t.type.toLowerCase().includes(lowerTerm)) ||
                (t.ip && t.ip.includes(lowerTerm)) ||
                (t.status && t.status.toLowerCase().includes(lowerTerm))
            );
        }

        return data;
    }, [traffic, searchTerm, severityFilter]);

    const stats = useMemo(() => {
        if (backendStats) {
            return backendStats;
        }

        const dataToUse = filteredTraffic;
        const total = dataToUse.length;
        const threats = dataToUse.filter(t => t.severity === 'High' || t.severity === 'Critical').length;
        const breaches = dataToUse.filter(t => {
            const size = parseFloat(t.response_size);
            return t.status_code === 200 && size > 5 && (t.severity === 'High' || t.severity === 'Critical');
        }).length;

        return {
            total,
            threats,
            breaches,
            health: Math.max(0, 100 - (threats * 2))
        };
    }, [filteredTraffic, backendStats]);

    return (
        <div className="p-6 space-y-6 pt-24 min-h-screen">
            {loadError && (
                <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-red-200 text-sm">
                    {loadError}
                </div>
            )}

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <StatCard
                    title="Total Events"
                    value={stats.total.toLocaleString()}
                    icon={Activity}
                    trend={searchTerm ? "Filtered" : "+0%"}
                    color="text-blue-500"
                />
                <StatCard
                    title="Threats Detected"
                    value={stats.threats.toLocaleString()}
                    icon={AlertTriangle}
                    
                    trend={searchTerm ? "Filtered" : "+0%"}
                    color="text-yellow-500"
                />
                <StatCard
                    title="Active Breaches"
                    value={stats.breaches.toLocaleString()}
                    icon={Lock}
                    trend={stats.breaches > 0 ? "CRITICAL" : "SECURE"}
                    color="text-red-500"
                    className={stats.breaches > 0 ? "animate-pulse border-red-500/50" : ""}
                />
                <StatCard
                    title="System Health"
                    value={`${stats.health}%`}
                    icon={Server}
                    trend="Stable"
                    color="text-green-500"
                />
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
                />
            </div>
        </div>
    );
}
