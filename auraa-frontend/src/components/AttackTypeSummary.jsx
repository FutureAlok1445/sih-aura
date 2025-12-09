// src/components/AttackTypeSummary.jsx
import React, { useMemo } from "react";
import { Shield, CheckCircle, AlertOctagon } from "lucide-react";

// Static knowledge base for mitigation advice
const MITIGATION_TIPS = {
  "SQL Injection": "Use prepared statements (parameterized queries) and validate all inputs.",
  "Cross-Site Scripting (XSS)": "Sanitize user input and use Content Security Policy (CSP).",
  "Command Injection": "Avoid system calls with user input; use specific libraries instead.",
  "Bruteforce Attack": "Implement rate limiting, account lockouts, and multi-factor authentication (MFA).",
  "Directory Traversal / LFI": "Validate file paths and use chrooted environments.",
  "Remote File Inclusion (RFI)": "Disable 'allow_url_include' in PHP configuration.",
  "SSRF": "Whitelist allowed outgoing domains and block internal IP ranges.",
  "XXE": "Disable external entity processing in your XML parser.",
  "Shell Upload Attempt": "Validate file types, rename uploaded files, and store them outside the web root.",
  "Benign": "Traffic appears normal. No action required."
};

export default function AttackTypeSummary({ attacks }) {
  // 1. Aggregate data: Count how many times each attack type appears
  const summary = useMemo(() => {
    if (!attacks || attacks.length === 0) return {};

    const counts = {};
    attacks.forEach((attack) => {
      const type = attack.type || "Unknown";
      // Skip Benign traffic in this summary to focus on threats
      if (type !== "Benign") {
        counts[type] = (counts[type] || 0) + 1;
      }
    });
    return counts;
  }, [attacks]);

  const attackTypes = Object.keys(summary);

  if (attackTypes.length === 0) {
    return (
      <div className="p-6 bg-black/40 border border-green-500/30 rounded-xl backdrop-blur-sm mt-6">
        <div className="flex items-center gap-3 text-green-400">
          <CheckCircle size={24} />
          <h3 className="text-xl font-bold">No Active Threats Detected</h3>
        </div>
        <p className="text-gray-400 mt-2 ml-9">
          The analyzed traffic appears clean. Keep monitoring for potential issues.
        </p>
      </div>
    );
  }

  return (
    <div className="p-6 bg-black/40 border border-white/10 rounded-xl backdrop-blur-sm mt-6">
      <div className="flex items-center gap-3 mb-6 border-b border-white/10 pb-4">
        <Shield className="text-blue-400" size={24} />
        <h3 className="text-xl font-bold text-white">
          Threat Analysis & Mitigation
        </h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {attackTypes.map((type) => (
          <div 
            key={type} 
            className="bg-white/5 border border-white/10 rounded-lg p-4 hover:border-red-500/50 transition-colors"
          >
            <div className="flex justify-between items-start mb-2">
              <h4 className="font-bold text-red-400 flex items-center gap-2">
                <AlertOctagon size={16} />
                {type}
              </h4>
              <span className="bg-red-500/20 text-red-300 text-xs px-2 py-1 rounded-full font-mono">
                {summary[type]} Events
              </span>
            </div>
            
            <div className="text-sm text-gray-300">
              <span className="text-gray-500 font-semibold block mb-1">Recommendation:</span>
              {MITIGATION_TIPS[type] || "Investigate traffic source and patch vulnerabilities."}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}