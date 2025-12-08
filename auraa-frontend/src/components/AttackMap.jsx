import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

// Data passed via props

const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
        return (
            <div className="bg-slate-900 border border-slate-700 p-3 rounded-lg shadow-xl">
                <p className="text-slate-400 text-xs mb-1">{label}</p>
                <p className="text-cyan-400 font-bold text-lg">
                    {payload[0].value} <span className="text-xs font-normal text-slate-500">attacks</span>
                </p>
            </div>
        );
    }
    return null;
};

const AttackMap = ({ data = [] }) => {
    return (
        <div className="h-full flex flex-col bg-slate-900/40 backdrop-blur-md border border-slate-800 rounded-2xl p-6">
            <h3 className="text-slate-300 font-medium mb-6">Global Attack Traffic</h3>
            <div className="flex-1 min-h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={data.length > 0 ? data : []}>
                        <defs>
                            <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                        <XAxis
                            dataKey="time"
                            stroke="#64748b"
                            fontSize={12}
                            tickLine={false}
                            axisLine={false}
                        />
                        <YAxis
                            stroke="#64748b"
                            fontSize={12}
                            tickLine={false}
                            axisLine={false}
                            tickFormatter={(value) => `${value}`}
                        />
                        <Tooltip content={<CustomTooltip />} />
                        <Area
                            type="monotone"
                            dataKey="attacks"
                            stroke="#22d3ee"
                            strokeWidth={3}
                            fillOpacity={1}
                            fill="url(#colorAttacks)"
                            isAnimationActive={false} // Disable animation for smoother real-time updates
                        />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
};

export default AttackMap;
