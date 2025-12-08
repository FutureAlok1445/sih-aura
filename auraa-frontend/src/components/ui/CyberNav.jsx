"use client";
import React, { useState } from "react";
import { motion } from "framer-motion";
import { NavLink } from "react-router-dom";
import { cn } from "../../lib/utils";

const navItems = [
    { name: "Intelligence Engine", path: "/" },
    { name: "Detection Rules", path: "/heuristics" },
    { name: "Documentation", path: "/docs" },
];

export function CyberNav() {
    const [hoveredPath, setHoveredPath] = useState(null);

    return (
        <div className="flex items-center gap-1 relative z-[100]">
            {navItems.map((item) => (
                <NavLink
                    key={item.path}
                    to={item.path}
                    className={({ isActive }) =>
                        cn(
                            "px-4 py-2 rounded-md text-sm font-medium relative no-underline duration-300 ease-in",
                            isActive ? "text-white" : "text-gray-400 hover:text-gray-200"
                        )
                    }
                    onMouseEnter={() => setHoveredPath(item.path)}
                    onMouseLeave={() => setHoveredPath(null)}
                >
                    <span>{item.name}</span>
                    {hoveredPath === item.path && (
                        <motion.div
                            className="absolute bottom-0 left-0 h-full w-full rounded-md -z-10 border border-white/50 bg-white/5"
                            layoutId="navbar-hover"
                            aria-hidden="true"
                            transition={{
                                type: "spring",
                                bounce: 0.25,
                                stiffness: 130,
                                damping: 9,
                                duration: 0.3,
                            }}
                        >
                            {/* Corner Accents for Cyber Look */}
                            <div className="absolute top-0 left-0 w-2 h-2 border-t border-l border-white" />
                            <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-white" />
                            <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-white" />
                            <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r border-white" />
                        </motion.div>
                    )}
                </NavLink>
            ))}
        </div>
    );
}
