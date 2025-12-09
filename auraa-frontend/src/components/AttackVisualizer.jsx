import React from "react";

export default function AttackVisualizer({ explanationData }) {
  if (!explanationData || explanationData.length === 0) return null;

  // --- STEP 1: Merge BERT Subwords (e.g., "log" + "##in" -> "login") ---
  const mergedTokens = [];
  explanationData.forEach((item) => {
    if (item.token.startsWith("##")) {
      // It's a piece of the previous word. Append it.
      if (mergedTokens.length > 0) {
        const prev = mergedTokens[mergedTokens.length - 1];
        prev.token += item.token.replace("##", ""); // Remove '##' and merge
        // Average the weight between the parts
        prev.weight = Math.max(prev.weight, item.weight); 
      }
    } else {
      // It's a new word start
      // Create a copy to avoid mutating the original prop
      mergedTokens.push({ ...item });
    }
  });

  return (
    <div className="mt-4 p-4 bg-black/40 rounded-lg border border-white/10">
      <h4 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
        🤖 AI Analysis Evidence
      </h4>
      
      <p className="text-gray-400 text-sm mb-4">
        The AI highlighted specific segments of this URL as suspicious. 
        <span className="text-red-400 font-bold ml-1">Red</span> indicates danger.
      </p>

      {/* The Clean URL Container */}
      <div className="flex flex-wrap items-center bg-gray-900 p-4 rounded-md font-mono text-sm break-all border border-gray-700 shadow-inner">
        {mergedTokens.map((item, index) => (
          <span
            key={index}
            className="px-[1px] transition-all duration-200 rounded cursor-help relative group"
            style={{
              backgroundColor: `rgba(255, 50, 50, ${item.weight * 0.8})`, // Transparency based on weight
              color: item.weight > 0.4 ? "#fff" : "#aaa",
              fontWeight: item.weight > 0.4 ? "bold" : "normal",
              borderBottom: item.weight > 0.4 ? "2px solid red" : "none"
            }}
          >
            {item.token}
            
            {/* Tooltip on Hover */}
            <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block bg-black text-white text-xs rounded p-1 whitespace-nowrap z-50 border border-white/20">
              Importance: {(item.weight * 100).toFixed(0)}%
            </span>
          </span>
        ))}
      </div>
    </div>
  );
}