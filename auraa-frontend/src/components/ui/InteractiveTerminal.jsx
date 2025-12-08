import React, { useState, useEffect } from 'react';
import { Lock, Wifi } from 'lucide-react';
import { motion } from 'framer-motion';

const bootLines = [
    "> KERNEL_INIT: LOADING AURA v2.4 MODULES...",
    "> NETWORK_INTERFACE: ETH0 UP [192.168.X.X]",
    "> HANDSHAKE: SECURE CONNECTION ESTABLISHED",
    "> LOADING_DB: THREAT SIGNATURES (SQLi, XSS, RCE)... [OK]",
    "> DETECTION_ENGINE: RESPONSE ANALYSIS ENGINE... [ONLINE]",
    "> SYSTEM_STATUS: MONITORING ACTIVE TRAFFIC...",
    "> READY."
];

export default function InteractiveTerminal() {
    const [lines, setLines] = useState([]);

    useEffect(() => {
        let delay = 0;
        bootLines.forEach((line) => {
            // Random typing delay for realism
            const randomDelay = Math.random() * 500 + 400;
            setTimeout(() => {
                setLines((prev) => [...prev, line]);
            }, delay);
            delay += randomDelay;
        });
    }, []);

    // Auto-scroll removed to prevent page scroll hijacking
    // The absolute positioning handles the "bottom-up" appearance visually

    return (
        <div className="w-full h-full flex flex-col font-mono text-sm relative z-10 overflow-hidden">

            {/* 1. Terminal Top Bar */}
            <div className="w-full h-8 bg-[#111] border-b border-white/10 flex items-center px-4 justify-between select-none">
                <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500/80" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500/80" />
                    <div className="w-3 h-3 rounded-full bg-green-500/80" />
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-500">
                    <span className="flex items-center gap-1"><Wifi className="w-3 h-3" /> CONNECTED</span>
                    <span className="flex items-center gap-1"><Lock className="w-3 h-3" /> ENCRYPTED</span>
                </div>
            </div>

            {/* 2. CRT Scanline Overlay (The "Retro/Tech" feel) */}
            <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] z-20 pointer-events-none bg-[length:100%_4px,6px_100%]" />

            {/* 3. Scrolling Text Area */}
            <div className="flex-1 p-6 md:p-8 text-left relative overflow-hidden">
                <div className="absolute bottom-0 left-0 w-full p-6 md:p-8">
                    {lines.map((line, i) => (
                        <motion.div
                            key={i}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            className="mb-2 font-medium tracking-wide"
                        >
                            <span className="text-blue-500 mr-2">➜</span>
                            <span className={line.includes("[OK]") ? "text-green-400" : "text-gray-300"}>
                                {line}
                            </span>
                        </motion.div>
                    ))}

                    {/* Blinking Cursor */}
                    <motion.span
                        animate={{ opacity: [0, 1, 0] }}
                        transition={{ repeat: Infinity, duration: 0.8 }}
                        className="inline-block w-2.5 h-5 bg-blue-500 ml-2 align-middle shadow-[0_0_10px_rgba(59,130,246,0.8)]"
                    />
                </div>
            </div>
        </div>
    );
}
