import React from 'react';
import { Link } from 'react-router-dom';
import { Rocket } from 'lucide-react';
import { HandWrittenTitle } from './ui/HandWrittenTitle';
import { CyberNav } from './ui/CyberNav';

export default function Navbar() {
    return (
        <nav className="fixed top-0 left-0 right-0 z-50 border-b border-white/10 bg-black/50 backdrop-blur-xl">
            <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
                {/* Left: Logo */}
                <div className="flex-shrink-0">
                    <Link to="/" className="flex items-center">
                        <HandWrittenTitle
                            title="AURA"
                            subtitle={null}
                            className="w-24 h-12 md:w-32 md:h-16"
                            textClassName="text-xl md:text-2xl"
                        />
                    </Link>
                </div>

                {/* Center: Navigation Links (Hidden on mobile, visible on md+) */}
                <div className="hidden md:flex justify-center items-center absolute left-1/2 -translate-x-1/2">
                    <CyberNav />
                </div>

                {/* Right: CTA */}
                <div className="flex-shrink-0">
                    <Link
                        to="/scan"
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-full text-xs md:text-sm font-bold transition-all shadow-[0_0_20px_rgba(59,130,246,0.3)] hover:shadow-[0_0_30px_rgba(59,130,246,0.5)]"
                    >
                        <Rocket className="w-3 h-3 md:w-4 md:h-4" />
                        <span className="hidden sm:inline">Initialize System</span>
                        <span className="sm:hidden">Scan</span>
                    </Link>
                </div>
            </div>
        </nav>
    );
}
