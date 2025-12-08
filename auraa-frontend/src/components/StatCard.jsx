import React from 'react';
import { motion } from 'framer-motion';
import clsx from 'clsx';

const StatCard = ({ title, value, icon: Icon, trend, color = 'cyan' }) => {
    const colorStyles = {
        cyan: 'text-cyan-400 border-cyan-500/20 shadow-cyan-500/10',
        rose: 'text-rose-500 border-rose-500/20 shadow-rose-500/10',
        emerald: 'text-emerald-400 border-emerald-500/20 shadow-emerald-500/10',
        violet: 'text-violet-400 border-violet-500/20 shadow-violet-500/10',
        blue: 'text-blue-400 border-blue-500/20 shadow-blue-500/10',
        yellow: 'text-yellow-400 border-yellow-500/20 shadow-yellow-500/10',
        red: 'text-red-400 border-red-500/20 shadow-red-500/10',
        green: 'text-green-400 border-green-500/20 shadow-green-500/10',
    };

    // Extract base color name if a full class string is passed (e.g., "text-blue-500" -> "blue")
    const getColorKey = (c) => {
        if (colorStyles[c]) return c;
        if (c.includes('blue')) return 'blue';
        if (c.includes('yellow')) return 'yellow';
        if (c.includes('red')) return 'red';
        if (c.includes('green')) return 'green';
        return 'cyan'; // Default
    };

    const activeColor = getColorKey(color);

    return (
        <motion.div
            whileHover={{ scale: 1.02, borderColor: `rgba(var(--${activeColor}-500), 0.5)` }}
            className={clsx(
                'relative p-6 rounded-2xl bg-slate-900/40 backdrop-blur-md border border-slate-800 transition-all duration-300 group overflow-hidden',
                `hover:shadow-[0_0_20px_rgba(0,0,0,0.3)]`
            )}
        >
            {/* Glow Effect on Hover */}
            <div className={clsx(
                'absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none',
                'bg-gradient-to-br from-white/5 to-transparent'
            )} />

            <div className="flex justify-between items-start mb-4">
                <div className="p-3 rounded-lg bg-slate-950/50 border border-slate-800 group-hover:border-slate-700 transition-colors">
                    <Icon className={clsx('w-6 h-6', colorStyles[activeColor].split(' ')[0])} />
                </div>
                {trend && (
                    <span className={clsx(
                        'text-xs font-medium px-2 py-1 rounded-full border',
                        trend > 0
                            ? 'text-emerald-400 border-emerald-500/20 bg-emerald-500/10'
                            : 'text-rose-400 border-rose-500/20 bg-rose-500/10'
                    )}>
                        {trend > 0 ? '+' : ''}{trend}%
                    </span>
                )}
            </div>

            <h3 className="text-slate-400 text-sm font-medium mb-1">{title}</h3>
            <div className="flex items-baseline gap-2">
                <h2 className="text-3xl font-bold text-white tracking-tight">{value}</h2>
            </div>
        </motion.div>
    );
};

export default StatCard;
