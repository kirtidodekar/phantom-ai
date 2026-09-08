import React, { useState, useEffect } from 'react';
import LandingPage from './components/LandingPage';
import AuthModal from './components/AuthModal';
import Navbar from './components/Navbar';
import OverviewPage from './components/OverviewPage';
import TopologyPage from './components/TopologyPage';
import ThreatIntelPage from './components/ThreatIntelPage';
import ForensicsPage from './components/ForensicsPage';
import ActionCenterPage from './components/ActionCenterPage';
import ModelDiagnosticsPage from './components/ModelDiagnosticsPage';
import MetricsModal from './components/MetricsModal';
import EntityDrawer from './components/EntityDrawer';

export default function App() {
  const [currentPage, setCurrentPage] = useState('landing');
  const [activeTab, setActiveTab] = useState('overview');
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [currentStage, setCurrentStage] = useState("Stage 5: Network SQLi Data Exfiltration");
  const [isReplaying, setIsReplaying] = useState(false);
  const [isMetricsOpen, setIsMetricsOpen] = useState(false);

  // User State & Auth Modal
  const [currentUser, setCurrentUser] = useState({
    name: 'Alex Rivera',
    email: 'alex@sentinel.ai',
    role: 'SOC Tier-2 Analyst'
  });
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState('login');

  // Entity Side Drawer State
  const [entityDrawerOpen, setEntityDrawerOpen] = useState(false);
  const [selectedEntityData, setSelectedEntityData] = useState(null);

  const fetchIncidents = async () => {
    try {
      const res = await fetch('/api/incidents');
      const data = await res.json();
      if (data && data.incidents) {
        setIncidents(data.incidents);
        if (data.incidents.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data.incidents[0].incident_id);
        }
      }
    } catch (err) {
      console.error("Error fetching incidents:", err);
    }
  };

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2500);
    return () => clearInterval(interval);
  }, []);

  const handleStartReplay = async () => {
    setIsReplaying(true);
    setCurrentStage("Executing Full 5-Stage Scenario...");
    try {
      await fetch('/api/replay/start', { method: 'POST' });
      await fetchIncidents();
      setCurrentStage("Stage 5: Network SQLi Data Exfiltration");
    } catch (err) {
      console.error("Error starting replay:", err);
    } finally {
      setIsReplaying(false);
    }
  };

  const handleStepReplay = async () => {
    try {
      const res = await fetch('/api/replay/step', { method: 'POST' });
      const data = await res.json();
      if (data.stage_name) {
        setCurrentStage(data.stage_name);
      }
      await fetchIncidents();
    } catch (err) {
      console.error("Error stepping replay:", err);
    }
  };

  const handleResetReplay = async () => {
    try {
      await fetch('/api/replay/reset', { method: 'POST' });
      setCurrentStage("Baseline Normal");
      await fetchIncidents();
    } catch (err) {
      console.error("Error resetting replay:", err);
    }
  };

  const handleLaunchDashboard = (role) => {
    const roleTitleMap = {
      'Analyst': 'SOC Tier-2 Analyst',
      'Engineer': 'Detection Engineer',
      'Commander': 'IR Commander'
    };
    setCurrentUser(prev => ({
      ...prev,
      role: roleTitleMap[role] || role
    }));
    setCurrentPage('dashboard');
  };

  const handleOpenAuth = (mode) => {
    setAuthModalMode(mode);
    setAuthModalOpen(true);
  };

  const handleLoginSuccess = (userData) => {
    setCurrentUser(userData);
    setCurrentPage('dashboard');
  };

  const handleOpenEntityDrawer = (data) => {
    setSelectedEntityData(data);
    setEntityDrawerOpen(true);
  };

  const activeIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0];
  const threatScore = activeIncident?.threat_score || 87;
  const threatLevel = activeIncident?.risk_breakdown?.risk_level || "CRITICAL";

  const renderActiveDashboardPage = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <OverviewPage
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={setSelectedIncidentId}
            activeIncident={activeIncident}
            currentStage={currentStage}
            onOpenEntity={handleOpenEntityDrawer}
          />
        );
      case 'topology':
        return (
          <TopologyPage
            activeIncident={activeIncident}
            onOpenEntity={handleOpenEntityDrawer}
          />
        );
      case 'intel':
        return <ThreatIntelPage activeIncident={activeIncident} />;
      case 'forensics':
        return <ForensicsPage activeIncident={activeIncident} />;
      case 'actions':
        return (
          <ActionCenterPage
            activeIncident={activeIncident}
            onRefreshIncident={fetchIncidents}
          />
        );
      case 'diagnostics':
        return <ModelDiagnosticsPage />;
      default:
        return (
          <OverviewPage
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={setSelectedIncidentId}
            activeIncident={activeIncident}
            currentStage={currentStage}
            onOpenEntity={handleOpenEntityDrawer}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#F5F7FA] text-slate-900 flex flex-col selection:bg-blue-600 selection:text-white">
      {currentPage === 'landing' ? (
        <LandingPage
          onLaunchDashboard={handleLaunchDashboard}
          onOpenAuth={handleOpenAuth}
        />
      ) : (
        <>
          {/* Persistent Navigation AppShell Header */}
          <Navbar
            activeTab={activeTab}
            onTabChange={setActiveTab}
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={setSelectedIncidentId}
            onStartReplay={handleStartReplay}
            onStepReplay={handleStepReplay}
            onResetReplay={handleResetReplay}
            onOpenMetrics={() => setIsMetricsOpen(true)}
            isReplaying={isReplaying}
            currentStage={currentStage}
            currentUser={currentUser}
            onGoHome={() => setCurrentPage('landing')}
            onOpenAuth={handleOpenAuth}
            threatScore={threatScore}
            threatLevel={threatLevel}
          />

          {/* Main Workspace */}
          <main className="flex-1 p-6 max-w-[1700px] w-full mx-auto space-y-6">
            {renderActiveDashboardPage()}
          </main>

          {/* Persistent Footer */}
          <footer className="border-t border-slate-200 bg-white px-6 py-2 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center space-x-4">
              <span className="flex items-center space-x-1.5 font-semibold text-slate-700">
                <span className={`w-2 h-2 rounded-full inline-block ${
                  threatScore >= 80 ? 'bg-rose-600' : threatScore >= 60 ? 'bg-amber-600' : 'bg-emerald-600'
                }`} />
                <span>INVESTIGATION FUSION: ONLINE</span>
              </span>
              <span>ANALYST: {currentUser.name} ({currentUser.role})</span>
              <span>INCIDENTS: {incidents.length}</span>
            </div>
            <div>SENTINEL AI | SOC INVESTIGATION WORKSTATION</div>
          </footer>
        </>
      )}

      {/* Contextual Entity Slide Drawer */}
      <EntityDrawer
        isOpen={entityDrawerOpen}
        onClose={() => setEntityDrawerOpen(false)}
        entityData={selectedEntityData}
        onNavigateTab={(tab) => {
          setActiveTab(tab);
          setEntityDrawerOpen(false);
        }}
      />

      {/* Auth & Session History Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        mode={authModalMode}
        onLoginSuccess={handleLoginSuccess}
      />

      {/* ML Model Report Modal */}
      <MetricsModal isOpen={isMetricsOpen} onClose={() => setIsMetricsOpen(false)} />
    </div>
  );
}
