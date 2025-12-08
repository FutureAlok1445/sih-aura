import React, { useMemo } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const COLORS = ['#f43f5e', '#fbbf24', '#22d3ee', '#a78bfa', '#34d399', '#f87171', '#818cf8', '#fb923c'];

const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
        return (
            <div className="bg-slate-900 border border-slate-700 p-2 rounded-lg shadow-xl">
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: payload[0].payload.fill }} />
                    <span className="text-slate-200 font-medium">{payload[0].name}</span>
                    <span className="text-slate-400">({payload[0].value})</span>
                </div>
            </div>
        );
    }
    return null;
};

const ThreatDonut = ({ data = [] }) => {
    const chartData = useMemo(() => {
        const counts = {};
        data.forEach(item => {
            const type = item.type || 'Unknown';
            counts[type] = (counts[type] || 0) + 1;
        });

        return Object.entries(counts)
            .map(([name, value], index) => ({
                name,
                value,
                fill: COLORS[index % COLORS.length]
            }))
            .sort((a, b) => b.value - a.value); // Sort by count descending (show ALL types)
    }, [data]);

    const totalThreats = data.length;

    if (totalThreats === 0) {
        return (
            <div className="h-full flex flex-col items-center justify-center bg-slate-900/40 backdrop-blur-md border border-slate-800 rounded-2xl p-6 text-slate-500">
                <p>No threat data available</p>
            </div>
        );
    }

    return (
        <div className="h-full flex flex-col bg-slate-900/40 backdrop-blur-md border border-slate-800 rounded-2xl p-6">
            <h3 className="text-slate-300 font-medium mb-4">Attack Vector Distribution</h3>
            <div className="flex-1 min-h-[350px] relative">
                <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                        <Pie
                            data={chartData}
                            cx="50%"
                            cy="45%"
                            innerRadius={50}
                            outerRadius={70}
                            paddingAngle={5}
                            dataKey="value"
                            stroke="none"
                        >
                            {chartData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.fill} />
                            ))}
                        </Pie>
                        <Tooltip content={<CustomTooltip />} />
                        <Legend
                            verticalAlign="bottom"
                            height={100}
                            iconType="circle"
                            wrapperStyle={{ fontSize: '11px', paddingTop: '10px' }}
                            formatter={(value) => <span className="text-slate-400 text-xs ml-1">{value}</span>}
                        />
                    </PieChart>
                </ResponsiveContainer>

                {/* Center Text */}
                <div className="absolute inset-0 flex items-center justify-center pointer-events-none" style={{ paddingBottom: '100px' }}>
                    <div className="text-center">
                        <p className="text-2xl font-bold text-white">{totalThreats}</p>
                        <p className="text-xs text-slate-500">Total Events</p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ThreatDonut;
