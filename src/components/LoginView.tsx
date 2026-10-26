import React, { useEffect, useState } from 'react';
import { ChevronDown, ChevronUp, Eye, EyeOff, Lock, LogIn, ShieldCheck } from 'lucide-react';
import { fetchDemoAccounts, fetchDemoStatus, loginApi } from '../client/api.ts';
import { ROLE_LABELS } from '../client/formatters.ts';
import type { UserProfile, UserRole } from '../shared/types.ts';

interface LoginViewProps {
  onAuthenticated: (user: UserProfile, demoMode?: boolean) => void;
  sessionNotice?: string | null;
}

export function LoginView({ onAuthenticated, sessionNotice }: LoginViewProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Server-controlled ENABLE_DEMO_MODE state (normal login page never loads credentials on mount)
  const [demoModeAvailable, setDemoModeAvailable] = useState(false);
  const [demoPanelOpen, setDemoPanelOpen] = useState(false);
  const [demoLoading, setDemoLoading] = useState(false);
  const [demoPassphrase, setDemoPassphrase] = useState<string | null>(null);
  const [demoAccounts, setDemoAccounts] = useState<
    Array<{
      email: string;
      fullName: string;
      role: UserRole;
      institutionName: string | null;
      isSyntheticDemo?: boolean;
    }>
  >([]);

  useEffect(() => {
    let active = true;
    fetchDemoStatus()
      .then((res) => {
        if (!active) return;
        const enabled = Boolean(res.demoMode);
        setDemoModeAvailable(enabled);
        if (!enabled) {
          setDemoPanelOpen(false);
          setDemoAccounts([]);
          setDemoPassphrase(null);
        }
      })
      .catch(() => {
        if (active) {
          setDemoModeAvailable(false);
          setDemoPanelOpen(false);
          setDemoAccounts([]);
          setDemoPassphrase(null);
        }
      });
    return () => {
      active = false;
    };
  }, []);

  const handleToggleDemoPanel = async () => {
    const nextOpen = !demoPanelOpen;
    setDemoPanelOpen(nextOpen);
    if (nextOpen && demoAccounts.length === 0 && !demoLoading) {
      setDemoLoading(true);
      try {
        const res = await fetchDemoAccounts();
        if (res.demoMode && res.accounts.length > 0) {
          setDemoAccounts(res.accounts);
          setDemoPassphrase(res.demoPassphrase || null);
        } else {
          setDemoModeAvailable(false);
          setDemoPanelOpen(false);
        }
      } catch {
        setDemoModeAvailable(false);
        setDemoPanelOpen(false);
      } finally {
        setDemoLoading(false);
      }
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
      setErrorMessage('Enter a valid institutional or officer email address.');
      return;
    }
    if (!password) {
      setErrorMessage('Enter your account password.');
      return;
    }

    setSubmitting(true);
    try {
      const result = await loginApi(trimmedEmail, password);
      onAuthenticated(result.user, result.demoMode);
    } catch (err) {
      setErrorMessage((err as Error).message || 'Authentication failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const handlePopulateDemoAccount = (targetEmail: string) => {
    setEmail(targetEmail);
    if (demoPassphrase) {
      setPassword(demoPassphrase);
    }
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col justify-between">
      {/* Institutional Top Header */}
      <header className="border-b border-slate-200 bg-slate-900 text-white px-6 py-4">
        <div className="max-w-5xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-baseline gap-3">
            <span className="font-display text-lg font-bold tracking-tight text-white">
              AUTHENTIX
            </span>
            <span className="hidden sm:inline text-slate-500" aria-hidden="true">
              |
            </span>
            <span className="text-xs sm:text-sm text-slate-300">
              Institutional Application &amp; Regulatory Verification
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-300">
            <ShieldCheck className="w-4 h-4 text-blue-300 shrink-0" />
            <span>Officer-Controlled Regulatory Scrutiny</span>
          </div>
        </div>
      </header>

      {/* Focused Institutional Sign-In Card */}
      <main className="flex-1 flex flex-col items-center justify-center px-4 py-10">
        <div className="w-full max-w-md space-y-4">
          <section className="bg-white border border-slate-200 rounded-lg shadow-xs p-7 space-y-6">
            <div className="space-y-1.5 border-b border-slate-100 pb-4">
              <h1 className="font-display text-xl font-bold text-slate-900">
                Authorised Officer Sign In
              </h1>
              <p className="text-sm text-slate-600">
                Sign in with your assigned scrutiny officer, vigilance auditor, administrator, or
                institution registrar credentials.
              </p>
            </div>

            {sessionNotice && (
              <div
                role="status"
                className="border border-amber-300 bg-amber-50 text-amber-900 rounded-md px-4 py-3 text-sm"
              >
                {sessionNotice}
              </div>
            )}

            {errorMessage && (
              <div
                role="alert"
                className="border border-red-300 bg-red-50 text-red-800 rounded-md px-4 py-3 text-sm"
              >
                {errorMessage}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              <div className="space-y-1.5">
                <label htmlFor="login-email" className="block text-sm font-medium text-slate-800">
                  Official Email Address
                </label>
                <input
                  id="login-email"
                  name="email"
                  type="email"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@institution.ac.in"
                  disabled={submitting}
                  className="w-full rounded-md border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-800 focus:outline-none focus:ring-2 focus:ring-blue-800/20 disabled:bg-slate-50"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label htmlFor="login-password" className="block text-sm font-medium text-slate-800">
                  Password
                </label>
                <div className="relative">
                  <input
                    id="login-password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter account password"
                    disabled={submitting}
                    className="w-full rounded-md border border-slate-300 pl-3.5 pr-16 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-800 focus:outline-none focus:ring-2 focus:ring-blue-800/20 disabled:bg-slate-50"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((prev) => !prev)}
                    aria-label={showPassword ? 'Conceal entry' : 'Reveal entry'}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                  >
                    {showPassword ? (
                      <>
                        <EyeOff className="w-3.5 h-3.5" />
                        <span>Hide</span>
                      </>
                    ) : (
                      <>
                        <Eye className="w-3.5 h-3.5" />
                        <span>Show</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="w-full min-h-[42px] inline-flex items-center justify-center gap-2 rounded-md bg-blue-950 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-900 disabled:opacity-60 transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-950 whitespace-nowrap"
              >
                <LogIn className="w-4 h-4 shrink-0" />
                <span>{submitting ? 'Verifying Credentials...' : 'Sign In to Scrutiny Console'}</span>
              </button>
            </form>

            <div className="pt-4 border-t border-slate-100 space-y-2 text-xs text-slate-500">
              <div className="flex items-center gap-2">
                <Lock className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                <span>Authenticated via server-side scrypt verification, session token, and CSRF protection.</span>
              </div>
              <p className="leading-relaxed">
                Automated document checks and advisory indicators assist scrutiny only. Final regulatory
                decisions require an authorised reviewing officer.
              </p>
            </div>
          </section>

          {/* Clearly Separated Development-Only Demo Access (Controlled by server ENABLE_DEMO_MODE) */}
          {demoModeAvailable && (
            <section
              aria-label="Development Demo Mode"
              className="border border-slate-300 bg-slate-100/80 rounded-lg overflow-hidden"
            >
              <button
                type="button"
                aria-expanded={demoPanelOpen}
                onClick={handleToggleDemoPanel}
                className="w-full px-4 py-3 flex items-center justify-between gap-3 text-left text-xs font-medium text-slate-700 hover:bg-slate-200/60 transition-colors"
              >
                <span>Development Demo Mode — Sample Evaluation Accounts (Disabled in Production)</span>
                {demoPanelOpen ? (
                  <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                )}
              </button>

              {demoPanelOpen && (
                <div className="px-4 pb-4 pt-2 border-t border-slate-200 bg-white space-y-3">
                  <p className="text-xs text-slate-600 leading-relaxed">
                    Server <code className="font-mono">ENABLE_DEMO_MODE=true</code> is active. Only synthetic{' '}
                    <code className="font-mono">*.demo</code> evaluation accounts and sample data are listed below.
                    Selecting an account populates the form and still verifies via server-side scrypt authentication.
                  </p>

                  {demoLoading ? (
                    <div className="py-3 text-xs text-slate-500">Loading synthetic evaluation accounts...</div>
                  ) : (
                    <>
                      {demoPassphrase && (
                        <div className="flex items-center justify-between gap-2 rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs">
                          <span className="text-slate-600">Synthetic Demo Passphrase:</span>
                          <code className="font-mono font-semibold text-slate-900 select-all">
                            {demoPassphrase}
                          </code>
                        </div>
                      )}

                      <div className="divide-y divide-slate-200 border border-slate-200 rounded-md">
                        {demoAccounts.map((acc) => (
                          <div
                            key={acc.email}
                            className="px-3 py-2.5 flex items-center justify-between gap-3 hover:bg-slate-50"
                          >
                            <div className="min-w-0">
                              <div className="text-xs font-semibold text-slate-900 truncate">
                                {ROLE_LABELS[acc.role]} — {acc.fullName}
                              </div>
                              <div className="text-xs text-slate-500 font-mono truncate">
                                {acc.email} · Synthetic Demo Account
                                {acc.institutionName ? ` · Scoped to ${acc.institutionName}` : ''}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => handlePopulateDemoAccount(acc.email)}
                              className="px-2.5 py-1 rounded border border-slate-300 bg-white text-xs font-medium text-blue-900 hover:bg-slate-100 whitespace-nowrap shrink-0"
                            >
                              Use Account
                            </button>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </section>
          )}
        </div>
      </main>

      <footer className="border-t border-slate-200 bg-white px-6 py-3.5 text-xs text-slate-500">
        <div className="max-w-5xl mx-auto flex flex-wrap items-center justify-between gap-4">
          <span>AUTHENTIX — Institutional Application &amp; Regulatory Verification</span>
          <span>Role-Based Access Control · Tamper-Evident Audit Logging</span>
        </div>
      </footer>
    </div>
  );
}
