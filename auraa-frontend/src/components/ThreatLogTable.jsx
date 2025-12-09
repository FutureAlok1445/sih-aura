import React, { useState } from "react";
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileJson,
  FileSpreadsheet,
  Download,
  Flag,
  Shield,
  FileText,
} from "lucide-react";
import FluidDropdown from "./ui/FluidDropdown";

export default function ThreatLogTable({
  attacks = [],
  onSearch,
  selectedSeverity = "All",
  onSeverityChange,
  onSelectAttack,
}) {
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  const itemsPerPage = 10;
  const filteredData = attacks;

  // Pagination Logic
  const totalPages = Math.ceil(filteredData.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedData = filteredData.slice(
    startIndex,
    startIndex + itemsPerPage
  );

  const handlePageChange = (newPage) => {
    if (newPage >= 1 && newPage <= totalPages) {
      setCurrentPage(newPage);
    }
  };

  const parseStatusCode = (statusCode) => {
    if (typeof statusCode === "number") return statusCode;
    if (typeof statusCode === "string") {
      const parsed = parseInt(statusCode, 10);
      if (!Number.isNaN(parsed)) return parsed;
    }
    return 0;
  };

  // Severity Badge
  const getSeverityBadge = (severityRaw) => {
    const severity = (severityRaw || "").toLowerCase();
    let colorClass = "bg-blue-500/10 text-blue-500 border-blue-500/20";
    if (severity === "critical")
      colorClass = "bg-red-500/10 text-red-500 border-red-500/20";
    else if (severity === "high")
      colorClass = "bg-orange-500/10 text-orange-500 border-orange-500/20";
    else if (severity === "medium")
      colorClass = "bg-yellow-500/10 text-yellow-500 border-yellow-500/20";

    return (
      <span
        className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${colorClass}`}
      >
        {severity ? severity.toUpperCase() : "UNKNOWN"}
      </span>
    );
  };

  // Decision Badge
  const getDecisionBadge = (statusCodeRaw) => {
    const statusCode = parseStatusCode(statusCodeRaw);
    if (statusCode >= 200 && statusCode < 300) {
      return (
        <span className="flex items-center gap-1 text-red-500 font-bold text-[10px] uppercase tracking-wider bg-red-500/10 px-2 py-1 rounded border border-red-500/20">
          <AlertTriangle className="w-3 h-3" /> Breach
        </span>
      );
    } else if (statusCode === 0) {
      return (
        <span className="flex items-center gap-1 text-yellow-500 font-bold text-[10px] uppercase tracking-wider bg-yellow-500/10 px-2 py-1 rounded border border-yellow-500/20">
          <Flag className="w-3 h-3" /> Unknown
        </span>
      );
    }
    return (
      <span className="flex items-center gap-1 text-emerald-500 font-bold text-[10px] uppercase tracking-wider bg-emerald-500/10 px-2 py-1 rounded border border-emerald-500/20">
        <ShieldCheck className="w-3 h-3" /> Blocked
      </span>
    );
  };

  // Export: only required fields
  const exportCSV = () => {
    const headers = [
      "Source IP",
      "Attack Type",
      "Method",
      "URL",
      "Post Body",
      "Status Code",
      "Severity",
      "Decision",
    ];

    const csvContent = [
      headers.join(","),
      ...filteredData.map((row) => {
        const sc = parseStatusCode(row.status_code);
        const decision =
          sc >= 200 && sc < 300
            ? "BREACH"
            : sc === 0
            ? "UNKNOWN"
            : "BLOCKED";
        const body = (row.post_body || "")
          .replace(/"/g, '""')
          .replace(/\n/g, " ");
        const url = (row.url || "").replace(/"/g, '""');
        return [
          row.ip, // Source IP
          row.attack_type || "", // Attack Type (from backend)
          row.method || "",
          `"${url}"`,
          `"${body}"`,
          row.status_code || "",
          row.severity || "",
          decision,
        ].join(",");
      }),
    ].join("\n");

    const blob = new Blob([csvContent], {
      type: "text/csv;charset=utf-8;",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aura_logs_${new Date().toISOString()}.csv`;
    link.click();
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(filteredData, null, 2)], {
      type: "application/json",
    });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `aura_logs_${new Date().toISOString()}.json`;
    link.click();
  };

  return (
    <div className="w-full space-y-4 p-6 border border-white/10 rounded-xl bg-black/40 backdrop-blur-md shadow-sm">
      {/* Header / Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-2">
        <div>
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-blue-500" />
            Live Threat Stream
          </h3>
          <p className="text-sm text-gray-500">
            Real-time analysis of HTTP traffic.
          </p>
        </div>
        <div className="flex flex-col sm:flex-row gap-3 w-full md:w-auto">
          <div className="relative w-full md:w-64">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search Logs..."
              className="w-full pl-10 pr-4 py-2 bg-black/50 border border-white/10 rounded-lg text-sm text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
              onChange={(e) => {
                if (onSearch) onSearch(e.target.value);
                setCurrentPage(1);
              }}
            />
          </div>
          <div className="relative z-10">
            <FluidDropdown
              selectedSeverity={selectedSeverity}
              onSeverityChange={onSeverityChange}
            />
          </div>
          <div className="relative">
            <button
              onClick={() => setIsExportOpen(!isExportOpen)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 text-sm font-medium rounded-lg border border-blue-500/20"
            >
              <Download className="w-4 h-4" /> Export
            </button>
            {isExportOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-black/90 border border-white/10 rounded-lg shadow-xl z-50 py-1">
                <button
                  onClick={() => {
                    exportCSV();
                    setIsExportOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10"
                >
                  <FileSpreadsheet className="w-4 h-4 text-green-400" /> CSV
                </button>
                <button
                  onClick={() => {
                    exportJSON();
                    setIsExportOpen(false);
                  }}
                  className="w-full flex items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10"
                >
                  <FileJson className="w-4 h-4 text-yellow-400" /> JSON
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
            <tr>
              <th className="px-6 py-3 font-medium">Source IP</th>
              <th className="px-6 py-3 font-medium">Attack Type</th>
              <th className="px-6 py-3 font-medium">Method</th>
              <th className="px-6 py-3 font-medium">URL / Endpoint</th>
              <th className="px-6 py-3 font-medium">Post Body</th>
              <th className="px-6 py-3 font-medium">Status</th>
              <th className="px-6 py-3 font-medium">Severity</th>
              <th className="px-6 py-3 font-medium">Final Decision</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/10">
            {paginatedData.length > 0 ? (
              paginatedData.map((attack, index) => (
                <tr
                  key={index}
                  onClick={() =>
                    onSelectAttack && onSelectAttack(attack)
                  }
                  className="hover:bg-blue-500/10 cursor-pointer transition-colors border-b border-white/5"
                >
                  {/* Source IP */}
                  <td className="px-6 py-3 font-mono text-xs text-blue-300">
                    {attack.ip}
                  </td>

                  {/* Attack Type */}
                  <td className="px-6 py-3 text-xs text-gray-300">
                    {attack.type || "-"}

                  </td>

                  {/* Method */}
                  <td className="px-6 py-3 font-mono text-xs">
                    <span
                      className={`px-1.5 py-0.5 rounded ${
                        attack.method === "POST"
                          ? "bg-orange-500/20 text-orange-400"
                          : "bg-gray-700 text-gray-300"
                      }`}
                    >
                      {attack.method || "GET"}
                    </span>
                  </td>

                  {/* URL */}
                  <td
                    className="px-6 py-3 text-gray-300 max-w-[200px] truncate"
                    title={attack.url}
                  >
                    {attack.url}
                  </td>

                  {/* Post Body */}
                  <td className="px-6 py-3 text-gray-400 max-w-[150px]">
                    {attack.post_body && attack.post_body.length > 0 ? (
                      <div className="group relative">
                        <div className="flex items-center gap-1 cursor-help text-xs text-gray-500">
                          <FileText className="w-3 h-3" />
                          <span className="truncate max-w-[100px]">
                            {attack.post_body}
                          </span>
                        </div>
                        {/* Tooltip for Body */}
                        <div className="absolute left-0 bottom-full mb-2 hidden group-hover:block w-64 bg-black border border-white/20 p-2 rounded text-xs text-gray-300 z-50 whitespace-pre-wrap break-all shadow-xl">
                          {attack.post_body}
                        </div>
                      </div>
                    ) : (
                      <span className="text-gray-600">-</span>
                    )}
                  </td>

                  {/* Status */}
                  <td className="px-6 py-3 font-mono text-xs">
                    {attack.status_code || "N/A"}
                  </td>

                  {/* Severity */}
                  <td className="px-6 py-3">
                    {getSeverityBadge(attack.severity)}
                  </td>

                  {/* Final Decision */}
                  <td className="px-6 py-3">
                    {getDecisionBadge(attack.status_code)}
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td
                  colSpan={8}
                  className="px-6 py-12 text-center text-gray-500"
                >
                  <div className="flex flex-col items-center gap-2">
                    <Shield className="w-8 h-8 opacity-20" />
                    <p>No traffic logs available</p>
                  </div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer / Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-4">
          <div className="text-xs text-gray-500">
            Page <span className="text-white">{currentPage}</span> of{" "}
            {totalPages}
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => handlePageChange(currentPage - 1)}
              disabled={currentPage === 1}
              className="px-3 py-1 text-xs bg-white/5 rounded hover:bg-white/10 disabled:opacity-50"
            >
              Prev
            </button>
            <button
              onClick={() => handlePageChange(currentPage + 1)}
              disabled={currentPage === totalPages}
              className="px-3 py-1 text-xs bg-white/5 rounded hover:bg-white/10 disabled:opacity-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
