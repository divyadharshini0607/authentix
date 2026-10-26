/**
 * AUTHENTIX — Institutional Application & Regulatory Verification
 */

import React, { useEffect, useState } from 'react';
import {
  Bell,
  BookOpenCheck,
  FileSpreadsheet,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  RotateCcw,
  X,
} from 'lucide-react';
import {
  fetchCurrentUser,
  fetchHealthStatus,
  fetchNotificationsApi,
  logoutApi,
  markAllNotificationsReadApi,
  markNotificationReadApi,
  registerUnauthorizedHandler,
  resetDemoEnvironmentApi,
} from './client/api.ts';
import { formatTimestamp, ROLE_LABELS, severityColorClass } from './client/formatters.ts';
import { ApplicationDetailView } from './components/ApplicationDetailView.tsx';
import { ApplicationsView } from './components/ApplicationsView.tsx';
import { DashboardView } from './components/DashboardView.tsx';
import { LoginView } from './components/LoginView.tsx';
import { ReportsAuditView } from './components/ReportsAuditView.tsx';
import { RulesGovernanceView } from './components/RulesGovernanceView.tsx';
import type { InAppNotificationRecord, UserProfile } from './shared/types.ts';

type WorkspaceSection = 'DASHBOARD' | 'APPLICATIONS' | 'DETAIL' | 'RULES' | 'REPORTS';

export interface ApplicationQueuePreset {
  priority?: string;
  status?: string;
  lifecycleStage?: string;
  category?: string;
}

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [demoMode, setDemoMode] = useState(false);
  const [bootstrapping, setBootstrapping] = useState(true);
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  const [section, setSection] = useState<WorkspaceSection>('DASHBOARD');
  const [selectedAppId, setSelectedAppId] = useState<string | null>(null);
  const [reportTargetAppId, setReportTargetAppId] = useState<string | null>(null);
  const [appQueuePreset, setAppQueuePreset] = useState<ApplicationQueuePreset | undefined>();

  // Persisted Scoped In-App Alerts (IN_APP_ONLY)
  const [alertsOpen, setAlertsOpen] = useState(false);
  const [notifications, setNotifications] = useState<InAppNotificationRecord[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [alertsDeliveryNotice, setAlertsDeliveryNotice] = useState(
    'Persisted in-app regulatory alerts only; external email and SMS gateways are not configured.'
  );
  const [alertsBusy, setAlertsBusy] = useState(false);

  // Safe inline confirmation for Admin Sample Dataset Reset (avoids window.confirm)
  const [confirmingReset, setConfirmingReset] = useState(false);
  const [resetBusy, setResetBusy] = useState(false);

  const refreshNotifications = async () => {
    try {
      const res = await fetchNotificationsApi();
      setNotifications(res.notifications);
      setUnreadCount(res.unreadCount);
      if (res.deliveryNotice) {
        setAlertsDeliveryNotice(res.deliveryNotice);
      }
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    registerUnauthorizedHandler(() => {
      setUser(null);
      setAlertsOpen(false);
      setNotifications([]);
      setUnreadCount(0);
      setSessionNotice('Your session expired or was signed out. Please sign in again.');
    });

    fetchCurrentUser()
      .then((res) => {
        setUser(res.user);
        if (typeof res.demoMode === 'boolean') {
          setDemoMode(res.demoMode);
        } else {
          fetchHealthStatus()
            .then((h) => setDemoMode(Boolean(h.demoMode)))
            .catch(() => {});
        }
      })
      .catch(() => {
        setUser(null);
      })
      .finally(() => {
        setBootstrapping(false);
      });

    return () => registerUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    if (user) {
      refreshNotifications();
    }
  }, [user?.id, section, selectedAppId]);

  const handleLogout = async () => {
    await logoutApi();
    setUser(null);
    setAlertsOpen(false);
    setNotifications([]);
    setUnreadCount(0);
    setSection('DASHBOARD');
    setSelectedAppId(null);
    setSessionNotice('You have signed out securely.');
  };

  const handleAdminReset = async () => {
    setResetBusy(true);
    try {
      await resetDemoEnvironmentApi();
      setConfirmingReset(false);
      setSelectedAppId(null);
      setSection('DASHBOARD');
      await refreshNotifications();
    } finally {
      setResetBusy(false);
    }
  };

  const handleMarkOneRead = async (notifId: string) => {
    setAlertsBusy(true);
    try {
      await markNotificationReadApi(notifId);
      await refreshNotifications();
    } finally {
      setAlertsBusy(false);
    }
  };

  const handleMarkAllRead = async () => {
    setAlertsBusy(true);
    try {
      await markAllNotificationsReadApi();
      await refreshNotifications();
    } finally {
      setAlertsBusy(false);
    }
  };

  if (bootstrapping) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center text-sm text-slate-600">
        Verifying session state...
      </div>
    );
  }

  if (!user) {
    return (
      <LoginView
        sessionNotice={sessionNotice}
        onAuthenticated={(authenticatedUser, isDemo) => {
          setSessionNotice(null);
          setUser(authenticatedUser);
          if (typeof isDemo === 'boolean') {
            setDemoMode(isDemo);
          }
          setSection('DASHBOARD');
        }}
      />
    );
  }

  const breadcrumbTrail = (() => {
    switch (section) {
      case 'DASHBOARD':
        return 'AUTHENTIX / Regulatory Scrutiny Overview';
      case 'APPLICATIONS':
        return 'AUTHENTIX / Applications Queue';
      case 'DETAIL':
        return 'AUTHENTIX / Applications / Case Review Workbench';
      case 'RULES':
        return 'AUTHENTIX / Versioned Regulatory Rules';
      case 'REPORTS':
        return 'AUTHENTIX / Validation Reports & Audit Log';
    }
  })();

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col md:flex-row">
      {/* Enterprise Navy Sidebar Navigation */}
      <aside className="w-full md:w-64 shrink-0 bg-slate-900 text-slate-200 border-b md:border-b-0 md:border-r border-slate-800 flex flex-col justify-between">
        <div className="p-5 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <div className="font-display text-lg font-bold tracking-tight text-white">
              AUTHENTIX
            </div>
            <div className="text-xs text-slate-400 mt-1 leading-snug">
              Institutional Application &amp; Regulatory Verification
            </div>
          </div>

          <nav aria-label="Primary Workspace Navigation" className="space-y-1">
            <button
              type="button"
              onClick={() => setSection('DASHBOARD')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                section === 'DASHBOARD'
                  ? 'bg-blue-900 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <LayoutDashboard className="w-4 h-4 shrink-0" />
              <span>Overview</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setAppQueuePreset(undefined);
                setSection('APPLICATIONS');
              }}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                section === 'APPLICATIONS' || section === 'DETAIL'
                  ? 'bg-blue-900 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <FolderKanban className="w-4 h-4 shrink-0" />
              <span>Applications</span>
            </button>

            <button
              type="button"
              onClick={() => setSection('RULES')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                section === 'RULES'
                  ? 'bg-blue-900 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <BookOpenCheck className="w-4 h-4 shrink-0" />
              <span>Regulatory Rules</span>
            </button>

            <button
              type="button"
              onClick={() => setSection('REPORTS')}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors whitespace-nowrap ${
                section === 'REPORTS'
                  ? 'bg-blue-900 text-white'
                  : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
            >
              <FileSpreadsheet className="w-4 h-4 shrink-0" />
              <span>Reports &amp; Audit</span>
            </button>
          </nav>
        </div>

        {/* Authenticated User Footer */}
        <div className="p-4 border-t border-slate-800 space-y-3">
          {demoMode && user.role === 'ADMIN' && (
            <div className="space-y-2">
              {!confirmingReset ? (
                <button
                  type="button"
                  onClick={() => setConfirmingReset(true)}
                  className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded border border-slate-700 text-xs text-slate-300 hover:bg-slate-800"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset Sample Dataset (Dev)</span>
                </button>
              ) : (
                <div className="p-2.5 rounded bg-slate-800 space-y-2 text-xs">
                  <p className="text-slate-200">Restore default development sample records?</p>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={resetBusy}
                      onClick={handleAdminReset}
                      className="flex-1 py-1 rounded bg-red-700 text-white font-medium"
                    >
                      {resetBusy ? 'Resetting...' : 'Confirm'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setConfirmingReset(false)}
                      className="flex-1 py-1 rounded border border-slate-600 text-slate-300"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="min-w-0">
            <div className="text-sm font-semibold text-white truncate">{user.fullName}</div>
            <div className="text-xs text-slate-400 truncate">
              {ROLE_LABELS[user.role]} · {user.email}
            </div>
            {user.institutionName && (
              <div className="text-xs text-slate-400 truncate mt-0.5">{user.institutionName}</div>
            )}
          </div>

          <button
            type="button"
            onClick={handleLogout}
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-md bg-slate-800 text-xs font-medium text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Clean Contextual Workspace Top Bar */}
        <header className="bg-white border-b border-slate-200 px-6 py-3.5 flex items-center justify-between gap-6 relative">
          <div className="flex items-center gap-3 min-w-0">
            <span className="text-xs font-medium text-slate-600 truncate">{breadcrumbTrail}</span>
            {demoMode && (
              <span className="hidden sm:inline text-xs font-mono text-amber-800">
                · Sample Data Mode (Development)
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              aria-expanded={alertsOpen}
              onClick={() => {
                const next = !alertsOpen;
                setAlertsOpen(next);
                if (next) {
                  refreshNotifications();
                }
              }}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md border border-slate-300 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0"
            >
              <Bell className="w-3.5 h-3.5 text-slate-600" />
              <span className="tabular-nums">
                In-App Alerts{unreadCount > 0 ? ` (${unreadCount})` : ''}
              </span>
            </button>

            <button
              type="button"
              onClick={() => {
                setAppQueuePreset(undefined);
                setSection('APPLICATIONS');
              }}
              className="px-3.5 py-1.5 rounded-md bg-slate-900 text-white text-xs font-semibold hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0"
            >
              Open Queue
            </button>
          </div>

          {alertsOpen && (
            <section
              aria-label="In-App Regulatory Alerts"
              className="absolute right-6 top-full mt-1.5 z-40 w-full max-w-md bg-white border border-slate-300 rounded-lg shadow-lg overflow-hidden"
            >
              <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between gap-3 bg-slate-50">
                <div>
                  <h2 className="font-display text-sm font-semibold text-slate-900">
                    In-App Regulatory Alerts ({unreadCount} unread)
                  </h2>
                  <p className="text-[11px] text-slate-500 mt-0.5">{alertsDeliveryNotice}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {unreadCount > 0 && (
                    <button
                      type="button"
                      disabled={alertsBusy}
                      onClick={handleMarkAllRead}
                      className="text-xs font-medium text-blue-800 hover:underline disabled:opacity-50"
                    >
                      Mark all read
                    </button>
                  )}
                  <button
                    type="button"
                    aria-label="Close alerts panel"
                    onClick={() => setAlertsOpen(false)}
                    className="p-1 rounded text-slate-500 hover:bg-slate-200/70"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {notifications.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500">
                  No persisted in-app alerts for your account scope.
                </div>
              ) : (
                <ul className="divide-y divide-slate-200 max-h-96 overflow-y-auto">
                  {notifications.map((n) => (
                    <li
                      key={n.id}
                      className={`p-4 space-y-1.5 text-xs ${n.isRead ? 'bg-white' : 'bg-blue-50/40'}`}
                    >
                      <div className="flex items-center justify-between gap-2 font-mono tabular-nums text-[11px] text-slate-500">
                        <span>
                          <span className={severityColorClass(n.severity)}>{n.severity}</span> ·{' '}
                          {n.deliveryChannel}
                        </span>
                        <span>{formatTimestamp(n.createdAt)}</span>
                      </div>
                      <div className="font-semibold text-slate-900">{n.title}</div>
                      <p className="text-slate-600 leading-snug">{n.message}</p>
                      <div className="flex items-center gap-3 pt-1">
                        {n.applicationId && (
                          <button
                            type="button"
                            onClick={() => {
                              setSelectedAppId(n.applicationId!);
                              setSection('DETAIL');
                              setAlertsOpen(false);
                              if (!n.isRead) {
                                handleMarkOneRead(n.id);
                              }
                            }}
                            className="font-semibold text-blue-900 hover:underline"
                          >
                            Open Case
                          </button>
                        )}
                        {!n.isRead && (
                          <button
                            type="button"
                            disabled={alertsBusy}
                            onClick={() => handleMarkOneRead(n.id)}
                            className="text-slate-600 hover:text-slate-900 hover:underline"
                          >
                            Mark read
                          </button>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          )}
        </header>

        <main className="flex-1 p-6 lg:p-8 max-w-[1360px] w-full mx-auto">
          {section === 'DASHBOARD' && (
            <DashboardView
              user={user}
              demoMode={demoMode}
              onOpenApplication={(appId) => {
                setSelectedAppId(appId);
                setSection('DETAIL');
              }}
              onNavigateApplications={(preset) => {
                setAppQueuePreset(preset);
                setSection('APPLICATIONS');
              }}
            />
          )}

          {section === 'APPLICATIONS' && (
            <ApplicationsView
              user={user}
              demoMode={demoMode}
              initialFilter={appQueuePreset}
              onOpenApplication={(appId) => {
                setSelectedAppId(appId);
                setSection('DETAIL');
              }}
            />
          )}

          {section === 'DETAIL' && selectedAppId && (
            <ApplicationDetailView
              applicationId={selectedAppId}
              user={user}
              demoMode={demoMode}
              onBack={() => setSection('APPLICATIONS')}
              onOpenReport={(appId) => {
                setReportTargetAppId(appId);
                setSection('REPORTS');
              }}
              onNotificationsChanged={refreshNotifications}
            />
          )}

          {section === 'RULES' && <RulesGovernanceView user={user} />}

          {section === 'REPORTS' && (
            <ReportsAuditView
              user={user}
              demoMode={demoMode}
              initialReportAppId={reportTargetAppId}
            />
          )}
        </main>
      </div>
    </div>
  );
}
