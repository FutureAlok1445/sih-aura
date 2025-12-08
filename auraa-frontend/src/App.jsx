import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Navbar from './components/Navbar';
import { BackgroundBeams } from './components/ui/BackgroundBeams';
import Home from './pages/Home';
import Scan from './pages/Scan';
import Dashboard from './pages/Dashboard';
import Docs from './pages/Docs';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen w-full bg-[#020408] relative flex flex-col antialiased selection:bg-blue-500 selection:text-white overflow-hidden">

        {/* The Background Layer */}
        <BackgroundBeams className="fixed inset-0 top-0 left-0 h-screen w-full pointer-events-none" />

        {/* The Content Layer */}
        <div className="relative z-10 flex flex-col h-full w-full">
          <Navbar />
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/docs" element={<Docs />} />
            <Route path="/heuristics" element={<Docs defaultTopic="detection-rules" />} />
          </Routes>
        </div>

      </div>
    </BrowserRouter>
  );
}

export default App;
