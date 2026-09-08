import React, { useState, useEffect, useRef, useCallback } from 'react';
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
import LiveMonitorPage from './components/LiveMonitorPage';
import AutoDefensePage from './components/AutoDefensePage';
import ThreatClassificationPage from './components/ThreatClassificationPage';
import IntegrationsPage from './components/IntegrationsPage';
import LiveNetworkPage from './components/LiveNetworkPage';
import CoveragePage from './components/CoveragePage';
import ErrorBoundary from './components/ErrorBoundary';
import { NotificationProvider, useNotifications } from './lib/notifications';
import { DefenseProvider } from './lib/defense';
import { api } from './lib/api';

/**
 * Bridges the defense store into the notification system so every automatic
 * or manual containment action also raises an admin alert.
 */
function DefenseBridge({ children }) {
  const { notify } = useNotifications();
  return <DefenseProvider onEvent={notify}>{children}</DefenseProvider>;
}

function AppShell() {
  const { notify } = useNotifications();

  const [currentPage, setCurrentPage] = useState('landing');
  const [activeTab, setActiveTab] = useState('overview');
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [currentStage, setCurrentStage] = useState("Stage 5: Network SQLi Data Exfiltration");
  const [isReplaying, setIsReplaying] = useState(false);
  const [isMetricsOpen, setIsMetricsOpen] = useState(false);
  const [backendOnline, setBackendOnline] = useState(true);
  // Global data-provenance indicator: LIVE capture vs DEMO/replay.
  const [networkMode, setNetworkMode] = useState('DEMO');

  const [currentUser, setCurrentUser] = useState({
    name: 'Alex Rivera',
    email: 'alex@sentinel.ai',
    role: 'SOC Tier-2 Analyst'
  });
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalMode, setAuthModalMode] = useState('login');

  const [entityDrawerOpen, setEntityDrawerOpen] = useState(false);
  const [selectedEntityData, setSelectedEntityData] = useState(null);

  // Tracks incidents already alerted on, so the 2.5s poll does not spam the
  // analyst with duplicate critical-threat notifications.
  const alertedRef = useRef(new Set());

  const fetchIncidents = useCallback(async () => {
    const data = await api.getIncidents();

    if (!data) {
      setBackendOnline(false);
      return;
    }
    setBackendOnline(true);

    const list = data.incidents || [];
    setIncidents(list);

    // Select the highest-scoring incident on first load without reading a ref
    // during render: the updater only fills an empty selection.
    if (list.length > 0) {
      setSelectedIncidentId((prev) => prev || list[0].incident_id);
    }

    // Admin alerting for critical threats.
    list.forEach((inc) => {
      const key = `${inc.incident_id}:${Math.round(inc.threat_score)}`;
      if (inc.threat_score >= 80 && !alertedRef.current.has(key)) {
        alertedRef.current.add(key);
        notify({
          severity: 'critical',
          title: `CRITICAL threat ${Math.round(inc.threat_score)}/100 — ${inc.incident_id}`,
          message: inc.title || `Escalation on ${inc.primary_entity}`,
        });
      }
    });
  }, [notify]);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2500);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  // Track whether live packet capture is active so the shell can label the
  // data source everywhere. Replay data must never look like real telemetry.
  useEffect(() => {
    let cancelled = false;
    const pollMode = async () => {
      const status = await api.getNetworkStatus();
      if (!cancelled && status?.mode) setNetworkMode(status.monitoring ? 'LIVE' : 'DEMO');
    };
    pollMode();
    const timer = setInterval(pollMode, 5000);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const handleStartReplay = async () => {
    setIsReplaying(true);
    setCurrentStage("Executing Full 5-Stage Scenario...");
    try {
      await api.startReplay();
      await fetchIncidents();
      setCurrentStage("Stage 5: Network SQLi Data Exfiltration");
      notify({ severity: 'info', title: 'Scenario replay complete', message: 'All 5 attack stages processed.' });
    } finally {
      setIsReplaying(false);
    }
  };

  const handleStepReplay = async () => {
    const data = await api.stepReplay();
    if (data?.stage_name) setCurrentStage(data.stage_name);
    await fetchIncidents();
  };

  const handleResetReplay = async () => {
    await api.resetReplay();
    alertedRef.current.clear();
    setCurrentStage("Baseline Normal");
    await fetchIncidents();
    notify({ severity: 'success', title: 'Investigation reset', message: 'Correlation state returned to baseline.' });
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
      case 'monitor':
        return <LiveMonitorPage onOpenEntity={handleOpenEntityDrawer} />;
      case 'network':
        return (
          <LiveNetworkPage
            currentUser={currentUser}
            onOpenEntity={handleOpenEntityDrawer}
          />
        );
      case 'topology':
        return <TopologyPage activeIncident={activeIncident} onOpenEntity={handleOpenEntityDrawer} />;
      case 'intel':
        return <ThreatIntelPage activeIncident={activeIncident} />;
      case 'forensics':
        return <ForensicsPage activeIncident={activeIncident} />;
      case 'actions':
        return <ActionCenterPage activeIncident={activeIncident} onRefreshIncident={fetchIncidents} />;
      case 'coverage':
        return <CoveragePage currentUser={currentUser} />;
      case 'defense':
        return <AutoDefensePage />;
      case 'classification':
        return <ThreatClassificationPage />;
      case 'diagnostics':
        return <ModelDiagnosticsPage />;
      case 'integrations':
        return <IntegrationsPage />;
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
        <LandingPage onLaunchDashboard={handleLaunchDashboard} onOpenAuth={handleOpenAuth} />
      ) : (
        <>
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

          {!backendOnline && (
            <div className="bg-amber-50 border-b border-amber-200 px-6 py-1.5 text-[11px] font-mono font-semibold text-amber-800 text-center">
              DETECTION API UNREACHABLE — showing last known state. Start the backend on port 8000 to resume live inference.
            </div>
          )}

          <main className="flex-1 p-6 max-w-[1700px] w-full mx-auto space-y-6">
            <ErrorBoundary resetKey={activeTab}>
              {renderActiveDashboardPage()}
            </ErrorBoundary>
          </main>

          <footer className="border-t border-slate-200 bg-white px-6 py-2 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center space-x-4">
              <span className="flex items-center space-x-1.5 font-semibold text-slate-700">
                <span className={`w-2 h-2 rounded-full inline-block ${
                  !backendOnline ? 'bg-slate-400' :
                  threatScore >= 80 ? 'bg-rose-600' : threatScore >= 60 ? 'bg-amber-600' : 'bg-emerald-600'
                }`} />
                <span>INVESTIGATION FUSION: {backendOnline ? 'ONLINE' : 'OFFLINE'}</span>
              </span>
              <span>ANALYST: {currentUser.name} ({currentUser.role})</span>
              <span>INCIDENTS: {incidents.length}</span>
              <span className={`px-1.5 py-0.5 rounded font-bold ${
                networkMode === 'LIVE'
                  ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                  : 'bg-slate-100 text-slate-600 border border-slate-200'
              }`}>
                {networkMode === 'LIVE' ? 'LIVE NETWORK TELEMETRY' : 'DEMO / REPLAY'}
              </span>
            </div>
            <div>SENTINEL AI | SOC INVESTIGATION WORKSTATION</div>
          </footer>
        </>
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
      <DefenseBridge>
        <AppShell />
      </DefenseBridge>
    </NotificationProvider>
  );
}
