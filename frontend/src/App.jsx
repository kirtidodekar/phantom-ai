import React, { useState, useEffect, useRef, useCallback } from 'react';
import LandingPage from './components/LandingPage';
import AuthModal from './components/AuthModal';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import OverviewPage from './components/OverviewPage';
import CoveragePage from './components/CoveragePage';
import TopologyPage from './components/TopologyPage';
import ThreatIntelPage from './components/ThreatIntelPage';
import ForensicsPage from './components/ForensicsPage';
import ActionCenterPage from './components/ActionCenterPage';
import IncidentDetails from './components/IncidentDetails';
import MetricsModal from './components/MetricsModal';
import EntityDrawer from './components/EntityDrawer';
import ErrorBoundary from './components/ErrorBoundary';
import { NotificationProvider, useNotifications } from './lib/notifications';
import { api } from './lib/api';

function AppShell() {
  const { notify } = useNotifications();

  const [currentPage, setCurrentPage] = useState('landing');
  const [activeTab, setActiveTab] = useState('overview');
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [currentStage, setCurrentStage] = useState('Multi-Signal Telemetry Ingestion');
  const [isSimulating, setIsSimulating] = useState(false);
  const [isMetricsOpen, setIsMetricsOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState(true);
  const [systemStatus, setSystemStatus] = useState(null);

  const [currentUser, setCurrentUser] = useState({
    name: 'Alex Rivera',
    email: 'alex@sentinel.ai',
    role: 'SOC Tier-2 Analyst'
  });
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState('login');

  const [entityDrawerOpen, setEntityDrawerOpen] = useState(false);
  const [selectedEntityData, setSelectedEntityData] = useState(null);

  const alertedRef = useRef(new Set());

  const fetchIncidents = useCallback(async () => {
    const list = await api.getIncidents();

    if (!list) {
      setBackendOnline(false);
      return;
    }
    setBackendOnline(true);
    setIncidents(list);

    if (list.length > 0) {
      setSelectedIncidentId((prev) => prev || list[0].id || list[0].incident_id);
    }

    // Alert analyst on high/critical threats
    list.forEach((inc) => {
      const incId = inc.id || inc.incident_id;
      const score = Math.round(inc.threat_score || 0);
      const key = `${incId}:${score}`;
      if (score >= 80 && !alertedRef.current.has(key)) {
        alertedRef.current.add(key);
        notify({
          severity: 'critical',
          title: `CRITICAL Threat Alert (${score}/100) — ${incId}`,
          message: inc.explanation || `Elevated risk on ${inc.entity_id || inc.primary_entity}`,
        });
      }
    });
  }, [notify]);

  const fetchSystemStatus = useCallback(async () => {
    const status = await api.getSystemStatus();
    if (status) {
      setSystemStatus(status);
      setBackendOnline(true);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    fetchSystemStatus();
    const interval = setInterval(() => {
      fetchIncidents();
      fetchSystemStatus();
    }, 3000);
    return () => clearInterval(interval);
  }, [fetchIncidents, fetchSystemStatus]);

  const handleStartSim = async () => {
    try {
      const res = await api.startSimulation();
      setIsSimulating(true);
      setCurrentStage('Simulated Multi-Signal Attack Campaign Running');
      notify({
        severity: 'success',
        title: 'Simulation Started',
        message: res?.message || 'Background multi-signal attack generator active.'
      });
      fetchIncidents();
    } catch (err) {
      notify({ severity: 'danger', title: 'Simulator Error', message: err.message });
    }
  };

  const handleStopSim = async () => {
    try {
      const res = await api.stopSimulation();
      setIsSimulating(false);
      setCurrentStage('Simulator Paused');
      notify({
        severity: 'info',
        title: 'Simulation Stopped',
        message: res?.message || 'Background generator paused.'
      });
      fetchIncidents();
    } catch (err) {
      notify({ severity: 'danger', title: 'Simulator Error', message: err.message });
    }
  };

  const handleLaunchDashboard = (role) => {
    const roleTitleMap = {
      'Analyst': 'SOC Tier-2 Analyst',
      'Engineer': 'Detection Engineer',
      'Commander': 'IR Commander'
    };
    setCurrentUser(prev => ({ ...prev, role: roleTitleMap[role] || role }));
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

  const activeIncident = incidents.find(i => (i.id === selectedIncidentId || i.incident_id === selectedIncidentId)) || incidents[0];
  const threatScore = activeIncident?.threat_score || 85;
  const threatLevel = activeIncident?.risk_band || (threatScore >= 80 ? 'CRITICAL' : threatScore >= 60 ? 'HIGH' : 'MEDIUM');

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
      case 'coverage':
        return <CoveragePage currentUser={currentUser} />;
      case 'topology':
        return <TopologyPage activeIncident={activeIncident} onOpenEntity={handleOpenEntityDrawer} />;
      case 'intel':
        return <ThreatIntelPage activeIncident={activeIncident} />;
      case 'forensics':
        return <ForensicsPage activeIncident={activeIncident} />;
      case 'actions':
        return <ActionCenterPage activeIncident={activeIncident} onRefreshIncident={fetchIncidents} />;
      case 'details':
        return (
          <div className="space-y-4">
            <div className="soc-surface p-5 border border-slate-200 flex justify-between items-center bg-gradient-to-r from-white to-blue-50/30">
              <div>
                <h1 className="text-sm font-extrabold text-slate-900">Incident Drill-Down & Raw Telemetry Inspector</h1>
                <p className="text-xs text-slate-500 font-medium">Direct API schema inspector querying GET /api/incidents/{'{id}'}</p>
              </div>
              <span className="font-mono text-xs font-bold text-blue-700 bg-blue-50 px-3 py-1 rounded-lg border border-blue-200">
                {activeIncident?.id || activeIncident?.incident_id}
              </span>
            </div>
            <IncidentDetails incident={activeIncident} incidentId={selectedIncidentId} />
          </div>
        );
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
    <div className="min-h-screen bg-[#F8FAFC] text-slate-900 flex flex-col selection:bg-blue-600 selection:text-white font-sans">
      {currentPage === 'landing' ? (
        <LandingPage onLaunchDashboard={handleLaunchDashboard} onOpenAuth={handleOpenAuth} />
      ) : (
        <div className="min-h-screen flex w-full">
          {/* Left Vertical Modern SaaS Navigation Sidebar */}
          <Sidebar
            activeTab={activeTab}
            onTabChange={setActiveTab}
            incidentsCount={incidents.length}
            isSimulating={isSimulating}
            onStartSim={handleStartSim}
            onStopSim={handleStopSim}
            currentUser={currentUser}
            onOpenAuth={handleOpenAuth}
            onGoHome={() => setCurrentPage('landing')}
            backendOnline={backendOnline}
            systemStatus={systemStatus}
          />

          {/* Right Main Content Area */}
          <div className="flex-1 flex flex-col min-w-0">
            {/* Top Command Bar */}
            <Header
              activeTab={activeTab}
              incidents={incidents}
              selectedIncidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              currentStage={currentStage}
              threatScore={threatScore}
              threatLevel={threatLevel}
              backendOnline={backendOnline}
              systemStatus={systemStatus}
            />

            {!backendOnline && (
              <div className="bg-amber-50 border-b border-amber-200 px-6 py-2 text-xs font-mono font-bold text-amber-900 text-center flex items-center justify-center gap-2">
                <span className="w-2 h-2 rounded-full bg-amber-600 animate-ping inline-block" />
                <span>BACKEND API UNREACHABLE — Operating in cached demonstration mode. Verify that your backend is running and reachable via VITE_API_BASE_URL.</span>
              </div>
            )}

            <main className="flex-1 p-6 max-w-[1720px] w-full mx-auto space-y-6">
              <ErrorBoundary resetKey={activeTab}>
                {renderActiveDashboardPage()}
              </ErrorBoundary>
            </main>

            {/* Bottom Status Bar */}
            <footer className="border-t border-slate-200/90 bg-white px-6 py-2.5 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-3 shadow-2xs">
              <div className="flex items-center gap-4 flex-wrap">
                <span className="flex items-center gap-1.5 font-bold text-slate-800">
                  <span className={`w-2 h-2 rounded-full inline-block ${
                    !backendOnline ? 'bg-slate-400' :
                    threatScore >= 80 ? 'bg-rose-600 animate-pulse' : threatScore >= 60 ? 'bg-amber-600' : 'bg-emerald-600'
                  }`} />
                  <span>SENTINEL API: {backendOnline ? 'ONLINE' : 'OFFLINE'}</span>
                </span>
                <span>SOVEREIGNTY: <strong className="text-emerald-700">{systemStatus?.sovereignty || '100% LOCAL_EXECUTION'}</strong></span>
                <span>ML ENGINE: <strong className="text-slate-800">{systemStatus?.ml_mode || 'IsolationForest'}</strong></span>
                <span>TOTAL INCIDENTS: <strong className="text-slate-900 font-extrabold">{incidents.length}</strong></span>
                <span>ANALYST: {currentUser.name} ({currentUser.role})</span>
              </div>
              <div className="font-bold text-slate-700">SENTINEL AI | SOC INVESTIGATION WORKSTATION (v2)</div>
            </footer>
          </div>
        </div>
      )}

      <EntityDrawer
        isOpen={entityDrawerOpen}
        onClose={() => setEntityDrawerOpen(false)}
        entityData={selectedEntityData}
        onNavigateTab={(tab) => {
          setActiveTab(tab);
          setEntityDrawerOpen(false);
        }}
      />

      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        mode={authModalMode}
        onLoginSuccess={handleLoginSuccess}
      />

      <MetricsModal isOpen={isMetricsOpen} onClose={() => setIsMetricsOpen(false)} />
    </div>
  );
}

export default function App() {
  return (
    <NotificationProvider>
      <AppShell />
    </NotificationProvider>
  );
}
