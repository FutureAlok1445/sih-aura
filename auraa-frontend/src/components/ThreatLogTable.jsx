import React, { useState } from "react";
import {
    Search,
    ShieldAlert,
    ShieldCheck,
    AlertTriangle,
    FileJson,
    FileSpreadsheet,
    Download,
    ChevronDown,
    Flag,
    Shield
} from "lucide-react";
import FluidDropdown from "./ui/FluidDropdown";

export default function ThreatLogTable({ attacks = [], onSearch, selectedSeverity = "All", onSeverityChange }) {
    const [isExportOpen, setIsExportOpen] = useState(false);
    const [currentPage, setCurrentPage] = useState(1);

    const itemsPerPage = 10;

    // Use passed attacks directly as they are filtered by parent
    const filteredData = attacks;

    // Pagination Logic
    const totalPages = Math.ceil(filteredData.length / itemsPerPage);
    const startIndex = (currentPage - 1) * itemsPerPage;
    const paginatedData = filteredData.slice(startIndex, startIndex + itemsPerPage);

    const handlePageChange = (newPage) => {
        if (newPage >= 1 && newPage <= totalPages) {
            setCurrentPage(newPage);
        }
    };

    // Helper: normalize status_code to integer (for decision logic)
    const parseStatusCode = (statusCode) => {
        if (typeof statusCode === "number") return statusCode;
        if (typeof statusCode === "string") {
            const parsed = parseInt(statusCode, 10);
            if (!Number.isNaN(parsed)) return parsed;
        }
        return 0;
    };

    // Severity badge (case-insensitive)
    const getSeverityBadge = (severityRaw) => {
        const severity = (severityRaw || "").toLowerCase();

        switch (severity) {
            case "critical":
                return (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-red-500/10 text-red-500 border border-red-500/20">
                        CRITICAL
                    </span>
                );
            case "high":
                return (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-orange-500/10 text-orange-500 border border-orange-500/20">
                        HIGH
                    </span>
                );
            case "medium":
                return (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-yellow-500/10 text-yellow-500 border border-yellow-500/20">
                        MEDIUM
                    </span>
                );
            default:
                return (
                    <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-blue-500/10 text-blue-500 border border-blue-500/20">
                        LOW
                    </span>
                );
        }
    };

    // Final Decision Badge: driven by status code (2xx = BREACH CONFIRMED)
    const getDecisionBadge = (type, statusCodeRaw) => {
        const statusCode = parseStatusCode(statusCodeRaw);

        if (statusCode >= 200 && statusCode < 300) {
            return (
                <span className="flex items-center gap-1.5 text-red-500 font-bold text-xs tracking-wide px-2 py-1 bg-red-500/10 rounded border border-red-500/20">
                    <AlertTriangle className="w-3 h-3" /> BREACH CONFIRMED
                </span>
            );
        } else if (statusCode === 0) {
            return (
                <span className="flex items-center gap-1.5 text-yellow-500 font-medium text-xs tracking-wide px-2 py-1 bg-yellow-500/10 rounded border border-yellow-500/20">
                    <Flag className="w-3 h-3" /> UNKNOWN
                </span>
            );
        }

        // Non-2xx, non-0 => Blocked
        return (
            <span className="flex items-center gap-1.5 text-emerald-500 font-medium text-xs tracking-wide px-2 py-1 bg-emerald-500/10 rounded border border-emerald-500/20">
                <ShieldCheck className="w-3 h-3" /> BLOCKED
            </span>
        );
    };

    const exportCSV = () => {
        const headers = [
            "Timestamp",
            "Source IP",
            "Target",
            "Attack Vector",
            "Severity",
            "Final Decision",
            "Status Code",
            "Response Size"
        ];

        const csvContent = [
            headers.join(","),
            ...filteredData.map((row) => {
                const statusCode = parseStatusCode(row.status_code);
                const finalDecision =
                    statusCode >= 200 && statusCode < 300
                        ? "BREACH CONFIRMED"
                        : statusCode === 0
                        ? "UNKNOWN"
                        : "BLOCKED";

                return [
                    row.timestamp,
                    row.ip,
                    `"${(row.target || "").replace(/"/g, '""')}"`,
                    row.type,
                    row.severity,
                    finalDecision,
                    row.status_code,
                    row.response_size
                ].join(",");
            })
        ].join("\n");

        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `aura_threat_logs_${new Date().toISOString()}.csv`;
        link.click();
    };

    const exportJSON = () => {
        const jsonContent = JSON.stringify(filteredData, null, 2);
        const blob = new Blob([jsonContent], { type: "application/json" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `aura_threat_logs_${new Date().toISOString()}.json`;
        link.click();
    };

    return (
        <div className="w-full space-y-4 p-6 border border-white/10 rounded-xl bg-black/40 backdrop-blur-md shadow-sm">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2">
                <div>
                    <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 text-blue-500" />
                        Live Threat Stream
                    </h3>
                    <p className="text-sm text-gray-500">Real-time analysis of incoming HTTP requests.</p>
                </div>

                {/* Actions */}
                <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
                    {/* Search Input */}
                    <div className="relative w-full md:w-64">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
                        <input
                            type="text"
                            placeholder="Search IP, Type, Status..."
                            className="w-full pl-10 pr-4 py-2 bg-black/50 border border-white/10 rounded-lg text-sm text-white placeholder:text-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-all"
                            onChange={(e) => {
                                if (onSearch) onSearch(e.target.value);
                                setCurrentPage(1);
                            }}
                        />
                    </div>

                    {/* Severity Filter */}
                    <div className="relative z-10">
                        <FluidDropdown
                            selectedSeverity={selectedSeverity}
                            onSeverityChange={(val) => {
                                if (onSeverityChange) onSeverityChange(val);
                                setCurrentPage(1);
                            }}
                        />
                    </div>

                    {/* Export Dropdown */}
                    <div className="relative">
                        <button
                            onClick={() => setIsExportOpen(!isExportOpen)}
                            className="flex items-center gap-2 px-4 py-2 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 text-sm font-medium rounded-lg border border-blue-500/20 transition-colors"
                        >
                            <Download className="w-4 h-4" />
                            Export Data
                            <ChevronDown
                                className={`w-4 h-4 transition-transform ${
                                    isExportOpen ? "rotate-180" : ""
                                }`}
                            />
                        </button>

                        {isExportOpen && (
                            <div className="absolute right-0 mt-2 w-48 bg-black/90 border border-white/10 rounded-lg shadow-xl backdrop-blur-xl z-50 py-1">
                                <button
                                    onClick={() => {
                                        exportCSV();
                                        setIsExportOpen(false);
                                    }}
                                    className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors text-left"
                                >
                                    <FileSpreadsheet className="w-4 h-4 text-green-400" />
                                    Export as CSV
                                </button>
                                <button
                                    onClick={() => {
                                        exportJSON();
                                        setIsExportOpen(false);
                                    }}
                                    className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-colors text-left"
                                >
                                    <FileJson className="w-4 h-4 text-yellow-400" />
                                    Export as JSON
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto rounded-lg border border-white/5">
                <table className="w-full text-sm text-left">
                    <thead className="text-xs text-gray-400 uppercase bg-white/5">
                        {/* Stage Headers (conceptual pipeline) */}
                        <tr className="border-b border-white/10">
                            <th
                                colSpan="3"
                                className="px-6 py-2 text-left font-bold text-blue-400 text-sm"
                            >
                                1. INGEST
                                <span className="ml-2 text-xs font-normal text-gray-500">
                                    Real-time IPDR/PCAP Stream
                                </span>
                            </th>
                            <th
                                colSpan="3"
                                className="px-6 py-2 text-left font-bold text-yellow-400 text-sm"
                            >
                                2. ANALYZE
                                <span className="ml-2 text-xs font-normal text-gray-500">
                                    Correlation Engine
                                </span>
                            </th>
                            <th
                                colSpan="1"
                                className="px-6 py-2 text-left font-bold text-red-400 text-sm"
                            >
                                3. FINAL DECISION
                                <span className="ml-2 text-xs font-normal text-gray-500">
                                    Classification
                                </span>
                            </th>
                        </tr>
                        {/* Column Headers */}
                        <tr>
                            <th className="px-6 py-3 font-medium">Timestamp</th>
                            <th className="px-6 py-3 font-medium">Source IP</th>
                            <th className="px-6 py-3 font-medium">Target</th>
                            <th className="px-6 py-3 font-medium">Attack Type</th>
                            <th className="px-6 py-3 font-medium">Severity</th>
                            <th className="px-6 py-3 font-medium">Status Code</th>
                            <th className="px-6 py-3 font-medium">Final Decision</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-white/10">
                        {paginatedData.length > 0 ? (
                            paginatedData.map((attack, index) => (
                                <tr
                                    key={index}
                                    className="hover:bg-white/5 transition-colors border-b border-white/5 last:border-0"
                                >
                                    <td className="px-6 py-3 text-gray-400 font-mono text-xs">
                                        {attack.timestamp
                                            ? new Date(attack.timestamp).toLocaleTimeString()
                                            : "-"}
                                    </td>

                                    {/* 1. INGEST */}
                                    <td className="px-6 py-3 font-mono text-xs text-blue-300">
                                        {attack.ip}
                                    </td>
                                    <td
                                        className="px-6 py-3 text-gray-400 max-w-[150px] truncate"
                                        title={attack.target || "/"}
                                    >
                                        {attack.target || "/"}
                                    </td>

                                    {/* 2. ANALYZE */}
                                    <td className="px-6 py-3 text-white font-medium">
                                        {attack.type}
                                    </td>
                                    <td className="px-6 py-3">
                                        {getSeverityBadge(attack.severity)}
                                    </td>
                                    <td className="px-6 py-3 text-xs text-gray-300">
                                        {attack.status_code !== undefined &&
                                        attack.status_code !== null &&
                                        attack.status_code !== ""
                                            ? attack.status_code
                                            : "N/A"}
                                    </td>

                                    {/* 3. FINAL DECISION */}
                                    <td className="px-6 py-3">
                                        {getDecisionBadge(attack.type, attack.status_code)}
                                    </td>
                                </tr>
                            ))
                        ) : (
                            <tr>
                                <td
                                    colSpan="7"
                                    className="px-6 py-12 text-center text-gray-500"
                                >
                                    <div className="flex flex-col items-center gap-2">
                                        <Shield className="w-8 h-8 opacity-20" />
                                        <p>No matching logs found</p>
                                    </div>
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <div className="flex items-center justify-between pt-4 border-t border-white/10">
                    <div className="text-sm text-gray-500">
                        Page{" "}
                        <span className="text-white font-medium">
                            {currentPage}
                        </span>{" "}
                        of{" "}
                        <span className="text-white font-medium">
                            {totalPages}
                        </span>
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={() => handlePageChange(currentPage - 1)}
                            disabled={currentPage === 1}
                            className="p-2 hover:bg-white/10 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                            Previous
                        </button>
                        <button
                            onClick={() => handlePageChange(currentPage + 1)}
                            disabled={currentPage === totalPages}
                            className="p-2 hover:bg-white/10 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                            Next
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
