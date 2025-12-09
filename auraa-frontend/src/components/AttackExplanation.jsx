import React, { useState, useEffect } from "react";
import { ShieldAlert, Info, Calendar, Globe, Bot } from "lucide-react";
import AttackVisualizer from "./AttackVisualizer"; 

export default function AttackExplanation({ selectedAttack }) {
  const [explanation, setExplanation] = useState(null);
  const [mitigation, setMitigation] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (selectedAttack) {
      setLoading(true);
      setExplanation(null);
      setMitigation("");

      // Ensure payload matches what Django expects
      const payload = { 
        attack_data: selectedAttack.url || selectedAttack.payload || "No payload data", 
        attack_type: selectedAttack.type || "Unknown"
      };

      fetch('http://127.0.0.1:8000/api/explain/', { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      .then(res => {
          if (!res.ok) throw new Error("API Request Failed");
          return res.json();
      })
      .then((data) => {
        setExplanation(data.explanation || []);
        setMitigation(data.mitigation || "No advice generated.");
        setLoading(false);
      })
      .catch(err => {
          console.error("Error fetching explanation:", err);
          setMitigation("Unable to connect to AI server. Please ensure the backend is running and HuggingFace tokens are valid.");
          setLoading(false);
      });
    }
  }, [selectedAttack]);

  const formatTime = (ts) => {
    if (!ts) return "N/A";
    try {
      const date = new Date(parseFloat(ts) * 1000); 
      return date.toLocaleString();
    } catch (e) {
      return ts;
    }
  };

  if (!selectedAttack) {
    return (
      <div className="p-8 border border-white/10 rounded-xl bg-black/20 text-center text-gray-500 flex flex-col items-center justify-center min-h-[200px]">
        <Info size={32} className="mb-3 opacity-50" />
        <p>Select an event from the table to view deep AI analysis.</p>
      </div>
    );
  }

  return (
    <div className="p-6 border border-white/10 rounded-xl bg-black/40 backdrop-blur-md shadow-xl transition-all duration-300">
      <div className="flex justify-between items-start mb-6 border-b border-white/10 pb-4">
        <div>
          <h3 className="text-2xl font-bold text-white flex items-center gap-2">
             {selectedAttack.type}
          </h3>
          <p className="text-red-400 text-sm font-mono mt-1 uppercase tracking-wider">
            {selectedAttack.severity || "HIGH"} SEVERITY
          </p>
        </div>
        <div className="text-right text-xs text-gray-500 space-y-1">
           <div className="flex items-center justify-end gap-2">
             <Calendar size={14} /> {formatTime(selectedAttack.timestamp)}
           </div>
           <div className="flex items-center justify-end gap-2">
             <Globe size={14} /> {selectedAttack.ip || "Unknown IP"}
           </div>
        </div>
      </div>

      {loading ? (
        <div className="p-8 text-center animate-pulse text-blue-400 bg-black/20 rounded-lg flex flex-col items-center justify-center min-h-[150px]">
          <Bot className="mb-2 animate-bounce" size={32} />
          <p className="font-mono text-sm">Initializing SecBERT & Gemma...</p>
          <p className="text-xs text-blue-500/50 mt-1">Calculating Integrated Gradients</p>
        </div>
      ) : (
        <AttackVisualizer explanationData={explanation} />
      )}

      {!loading && mitigation && (
        <div className="mt-6 bg-blue-900/10 border-l-4 border-blue-500 p-4 rounded-r-lg hover:bg-blue-900/20 transition-colors">
          <div className="flex items-start gap-3">
            <ShieldAlert className="text-blue-400 shrink-0 mt-1" size={24} />
            <div className="w-full">
              <h4 className="font-bold text-blue-100 text-sm uppercase mb-2 flex items-center gap-2">
                AI Mitigation Strategy
                <span className="text-[10px] bg-blue-500/20 text-blue-300 px-2 py-0.5 rounded-full border border-blue-500/30">
                  GEMMA-3 ENHANCED
                </span>
              </h4>
              <pre className="text-gray-300 text-sm leading-relaxed whitespace-pre-wrap font-sans bg-transparent border-none p-0 m-0">
                {mitigation}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}