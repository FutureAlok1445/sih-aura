import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDropzone } from 'react-dropzone';
import { motion, AnimatePresence } from 'framer-motion';
import Spotlight from '../components/ui/Spotlight';
import { Upload, Terminal, File } from 'lucide-react';
import clsx from 'clsx';

export default function Scan() {
    const navigate = useNavigate();
    const [isScanning, setIsScanning] = useState(false);
    const [scanStep, setScanStep] = useState(0);
    const [files, setFiles] = useState([]);

    const handleScan = (e) => {
        e?.preventDefault();
        setIsScanning(true);

        // Simulation sequence
        setTimeout(() => setScanStep(1), 1000); // Parsing
        setTimeout(() => setScanStep(2), 2000); // Analyzing
        setTimeout(() => navigate('/dashboard'), 3000); // Redirect
    };

    const onDrop = useCallback((acceptedFiles) => {
        setFiles(acceptedFiles);
    }, []);

    const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
        onDrop,
        accept: {
            'application/vnd.tcpdump.pcap': ['.pcap', '.cap'],
            'application/x-pcapng': ['.pcapng'],
            'application/octet-stream': ['.pcap', '.cap', '.pcapng']
        },
        maxFiles: 1
    });

    return (
        <div className="min-h-screen flex items-center justify-center pt-20 px-4">
            <AnimatePresence mode="wait">
                {!isScanning ? (
                    <motion.div
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95 }}
                        className="w-full max-w-2xl"
                    >
                        <div className="text-center mb-10">
                            <h1 className="text-4xl font-bold text-white mb-4 tracking-tight">Command Console</h1>
                            <p className="text-gray-400">Initiate deep packet inspection or URL analysis</p>
                        </div>

                        <Spotlight className="p-1">
                            <div className="bg-black/80 rounded-xl p-6 min-h-[450px] flex flex-col">
                                {/* Tabs */}
                                <div className="flex gap-4 mb-8 border-b border-white/10 pb-4">
                                    <button
                                        className={clsx("pb-2 text-sm font-bold transition-colors relative text-blue-400")}
                                    >
                                        Packet Analysis Upload
                                        <motion.div layoutId="tab" className="absolute bottom-[-17px] left-0 right-0 h-0.5 bg-blue-400" />
                                    </button>
                                </div>

                                {/* Content */}
                                <div className="flex-1 flex flex-col justify-center">
                                    <div className="space-y-6">
                                        <div
                                            {...getRootProps()}
                                            className={clsx(
                                                "border-2 border-dashed rounded-xl p-10 flex flex-col items-center justify-center text-center cursor-pointer transition-colors h-48",
                                                isDragActive ? "border-blue-500 bg-blue-500/10" : "border-white/10 hover:border-white/20 hover:bg-white/5"
                                            )}
                                        >
                                            <input {...getInputProps()} />
                                            <Upload className={clsx("w-12 h-12 mb-4", isDragActive ? "text-blue-400" : "text-gray-500")} />
                                            <p className="text-gray-300 font-medium">Drag & drop PCAP file</p>
                                            <p className="text-gray-500 text-sm mt-2">Supports .pcap, .cap, .pcapng</p>
                                        </div>

                                        {files.length > 0 && (
                                            <div className="bg-white/5 rounded-lg p-3 flex items-center gap-3 border border-white/10">
                                                <File className="w-5 h-5 text-blue-400" />
                                                <span className="text-sm text-gray-300 font-mono flex-1 truncate">{files[0].name}</span>
                                                <span className="text-xs text-gray-500">{(files[0].size / 1024).toFixed(1)} KB</span>
                                            </div>
                                        )}

                                        {fileRejections.length > 0 && (
                                            <div className="bg-red-500/10 rounded-lg p-3 flex items-center gap-3 border border-red-500/20">
                                                <div className="w-5 h-5 flex items-center justify-center rounded-full bg-red-500/20 text-red-500 font-bold text-xs">!</div>
                                                <span className="text-sm text-red-400 font-mono">Invalid file type. Only PCAP files allowed.</span>
                                            </div>
                                        )}

                                        <button
                                            onClick={handleScan}
                                            disabled={files.length === 0}
                                            className="w-full py-4 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 disabled:text-gray-500 text-white font-bold rounded-lg transition-all shadow-[0_0_20px_rgba(37,99,235,0.3)] disabled:shadow-none"
                                        >
                                            EXECUTE FORENSIC ANALYSIS
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </Spotlight>
                    </motion.div>
                ) : (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="w-full max-w-4xl font-mono"
                    >
                        <div className="bg-black/90 border border-green-500/30 p-8 rounded-xl shadow-[0_0_50px_rgba(34,197,94,0.1)]">
                            <div className="flex items-center gap-3 mb-6 border-b border-green-900/50 pb-4">
                                <Terminal className="w-5 h-5 text-green-500" />
                                <span className="text-green-500 font-bold">SYSTEM_ROOT@AURA:~#</span>
                            </div>

                            <div className="space-y-2 text-sm">
                                <div className="text-green-400">
                                    {'>'} Initializing detection engine... <span className="text-green-200">[OK]</span>
                                </div>
                                {scanStep >= 1 && (
                                    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-green-400">
                                        {'>'} Parsing packet headers... <span className="text-green-200">[COMPLETE]</span>
                                    </motion.div>
                                )}
                                {scanStep >= 2 && (
                                    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-green-400">
                                        {'>'} Analyzing response signatures... <span className="text-red-400">[BREACH CONFIRMED]</span>
                                    </motion.div>
                                )}
                                <motion.div
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: [0, 1, 0] }}
                                    transition={{ repeat: Infinity, duration: 0.8 }}
                                    className="w-3 h-5 bg-green-500 mt-4"
                                />
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
