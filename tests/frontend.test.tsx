// @vitest-environment jsdom
/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Frontend React Component & Workflow Interaction Tests
 * Connects the actual React UI (<App />) in JSDOM to the live ephemeral Express + SQLite
 * server started by `tests/globalSetup.ts` (`process.env.VITEST_UI_API_URL`).
 */

import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import App from '../src/App.tsx';
import { clearAuthTokens } from '../src/client/api.ts';

const DEMO_PASSWORD = process.env.DEMO_SEED_PASSWORD || 'Authentix@SIH2026!';

describe('AUTHENTIX Frontend UI & Real Backend Integration Suite', () => {
  const originalFetch = globalThis.fetch;
  let simulateServiceOutage = false;
  let simulateRulesError = false;
  let simulateDemoModeDisabled = false;
  let demoAccountsFetchCount = 0;

  beforeAll(() => {
    const baseUrl = process.env.VITEST_UI_API_URL;
    if (!baseUrl) {
      throw new Error('VITEST_UI_API_URL missing — globalSetup did not initialize test server.');
    }

    // Route relative `/api/*` requests in JSDOM to the real running Express + SQLite test server
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (typeof input === 'string' && input.startsWith('/api/auth/demo-accounts')) {
        demoAccountsFetchCount += 1;
        if (simulateDemoModeDisabled) {
          return new Response(
            JSON.stringify({ demoMode: false, accounts: [], error: 'Demo mode is disabled (ENABLE_DEMO_MODE=false).' }),
            { status: 403, headers: { 'Content-Type': 'application/json' } }
          );
        }
      }
      if (simulateDemoModeDisabled && typeof input === 'string' && input.startsWith('/api/auth/demo-status')) {
        return new Response(JSON.stringify({ demoMode: false }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (simulateServiceOutage && typeof input === 'string' && input.startsWith('/api/auth/login')) {
        return new Response(
          JSON.stringify({ error: 'Authentication database temporarily unavailable (503).' }),
          { status: 503, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (simulateRulesError && typeof input === 'string' && input.startsWith('/api/rules')) {
        return new Response(
          JSON.stringify({ error: 'Unable to load validation rules right now.' }),
          { status: 500, headers: { 'Content-Type': 'application/json' } }
        );
      }
      if (typeof input === 'string' && input.startsWith('/')) {
        return originalFetch(`${baseUrl}${input}`, init);
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    if (!URL.createObjectURL) {
      URL.createObjectURL = () => 'blob:http://localhost/mock-preview';
    }
    if (!URL.revokeObjectURL) {
      URL.revokeObjectURL = () => {};
    }
  });

  afterEach(() => {
    simulateServiceOutage = false;
    simulateRulesError = false;
    simulateDemoModeDisabled = false;
    demoAccountsFetchCount = 0;
    cleanup();
    clearAuthTokens();
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  it('1. renders clean institutional login without visible credentials or SIH copy, supports separated dev demo mode, rejects bad passwords, and signs in/out', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('Authorised Officer Sign In')).toBeInTheDocument();
    });

    // Verify institutional branding and absence of SIH / Synthetic Demonstration copy or exposed credentials on standard view
    expect(screen.getAllByText('AUTHENTIX').length).toBeGreaterThan(0);
    expect(
      screen.getAllByText(/Institutional Application & Regulatory Verification/i).length
    ).toBeGreaterThan(0);
    expect(screen.queryByText(/Synthetic Demonstration/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/SIH26261/i)).not.toBeInTheDocument();
    expect(screen.queryByText('officer@authentix.demo')).not.toBeInTheDocument();
    expect(screen.queryByText(DEMO_PASSWORD)).not.toBeInTheDocument();

    // Empty / invalid email check
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/valid institutional or officer email/i);

    // Wrong password check against real backend
    fireEvent.change(screen.getByLabelText(/Official Email Address/i), {
      target: { value: 'officer@authentix.demo' },
    });
    fireEvent.change(screen.getByLabelText(/Password/i), {
      target: { value: 'WrongPass999' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Invalid email address or password/i);

    // Normal login page must NOT even request /api/auth/demo-accounts until Demo Mode toggle is opened
    const demoToggle = await screen.findByRole('button', {
      name: /Development Demo Mode — Sample Evaluation Accounts/i,
    });
    expect(demoAccountsFetchCount).toBe(0);
    expect(screen.queryByText('officer@authentix.demo')).not.toBeInTheDocument();
    expect(screen.queryByText(DEMO_PASSWORD)).not.toBeInTheDocument();

    // Open separated Development Demo Mode drawer and populate sample officer account
    fireEvent.click(demoToggle);
    expect(await screen.findByText(/officer@authentix\.demo · Synthetic Demo Account/i)).toBeInTheDocument();
    expect(demoAccountsFetchCount).toBe(1);
    const useAccountButtons = screen.getAllByRole('button', { name: /Use Account/i });
    fireEvent.click(useAccountButtons[0]);

    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));

    await waitFor(() => {
      expect(screen.getByText('Regulatory Scrutiny Overview')).toBeInTheDocument();
    });

    // Confirm dashboard KPIs, review status distribution, and real persisted applications
    expect(screen.getByText('Compliance Findings')).toBeInTheDocument();
    expect(screen.getByText('Review Status Distribution')).toBeInTheDocument();
    expect(await screen.findByText('APP-2026-0102')).toBeInTheDocument();
    expect(screen.getByText('Kaveri Valley Technical Campus')).toBeInTheDocument();

    // Sign Out
    fireEvent.click(screen.getByRole('button', { name: /Sign Out/i }));
    await waitFor(() => {
      expect(screen.getByText('Authorised Officer Sign In')).toBeInTheDocument();
    });
  });

  it('2. filters applications, opens case workbench, validates bad file uploads, displays findings, and persists officer review notes', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByLabelText(/Official Email Address/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/Official Email Address/i), {
      target: { value: 'officer@authentix.demo' },
    });
    fireEvent.change(screen.getByLabelText(/Password/i), {
      target: { value: DEMO_PASSWORD },
    });
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));

    await waitFor(() => {
      expect(screen.getByText('Regulatory Scrutiny Overview')).toBeInTheDocument();
    });

    // Navigate to Applications Queue
    fireEvent.click(screen.getByRole('button', { name: /^Applications$/i }));
    await waitFor(() => {
      expect(screen.getByText('Applications & Scrutiny Queue')).toBeInTheDocument();
    });

    // Search for Kaveri Valley
    const searchInput = screen.getByLabelText('Search applications');
    fireEvent.change(searchInput, { target: { value: 'Kaveri Valley' } });

    await waitFor(() => {
      expect(screen.getByText('APP-2026-0102')).toBeInTheDocument();
    });

    // Open APP-2026-0102 Detail Workbench
    fireEvent.click(screen.getByText('APP-2026-0102'));

    await waitFor(() => {
      expect(screen.getByText(/Upload & Authenticate Supporting Document/i)).toBeInTheDocument();
    });

    // Test client-side file type validation error
    const fileInput = screen.getByLabelText(/Document File/i);
    const invalidTxtFile = new File(['hello'], 'notes.txt', { type: 'text/plain' });
    fireEvent.change(fileInput, { target: { files: [invalidTxtFile] } });
    expect(await screen.findByRole('alert')).toHaveTextContent(/Only PDF/i);

    // Switch to Validation & Anomaly Findings tab and verify evidence display
    fireEvent.click(screen.getByRole('tab', { name: /Validation & Anomaly Findings/i }));
    expect(await screen.findByText(/RULE-DOC-EXPIRY/i)).toBeInTheDocument();
    expect(screen.getByText(/RULE-INTAKE-MATCH/i)).toBeInTheDocument();

    // Verify 4-category epistemic verification summary is rendered clearly
    expect(screen.getByText(/1\. Verified Facts/i)).toBeInTheDocument();
    expect(screen.getByText(/2\. Rule-Based Flags/i)).toBeInTheDocument();
    expect(screen.getByText(/3\. Unavailable Checks/i)).toBeInTheDocument();
    expect(screen.getByText(/4\. Manual-Review Requirements/i)).toBeInTheDocument();

    // Switch to Officer Review & Decision tab and submit a persistent review note
    fireEvent.click(screen.getByRole('tab', { name: /Officer Review & Decision/i }));
    const rationaleBox = await screen.findByLabelText(/Officer Explanation \/ Rationale/i);
    fireEvent.change(rationaleBox, {
      target: { value: 'UI Test Review Note: Fire certificate expired; clarification needed.' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Submit & Persist Officer Action/i }));

    expect(
      await screen.findByText(/UI Test Review Note: Fire certificate expired; clarification needed\./i)
    ).toBeInTheDocument();
    expect(screen.getByText(/Case Audit Trail \(SHA-256 Hash-Chained\)/i)).toBeInTheDocument();

    // Simulate full browser refresh: unmount React tree WITHOUT clearing sessionStorage, then re-mount <App />
    cleanup();
    render(<App />);

    // Session should restore automatically via /api/auth/me without returning to login screen
    await waitFor(() => {
      expect(screen.getByText('Regulatory Scrutiny Overview')).toBeInTheDocument();
    });

    // Re-open APP-2026-0102 and confirm officer note persisted in SQLite across refresh
    fireEvent.click(await screen.findByText('APP-2026-0102'));
    fireEvent.click(await screen.findByRole('tab', { name: /Officer Review & Decision/i }));
    expect(
      await screen.findByText(/UI Test Review Note: Fire certificate expired; clarification needed\./i)
    ).toBeInTheDocument();
  });

  it('3. surfaces backend unavailable (503) and upstream source-unavailability states without reporting false success', async () => {
    simulateServiceOutage = true;
    render(<App />);

    await waitFor(() => {
      expect(screen.getByLabelText(/Official Email Address/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/Official Email Address/i), {
      target: { value: 'officer@authentix.demo' },
    });
    fireEvent.change(screen.getByLabelText(/Password/i), {
      target: { value: DEMO_PASSWORD },
    });
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));

    // Confirm 503 outage is surfaced clearly in an accessible alert
    expect(await screen.findByRole('alert')).toHaveTextContent(/temporarily unavailable \(503\)/i);

    // Recover from outage and inspect APP-2026-0105 upstream source unavailability
    simulateServiceOutage = false;
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));

    await waitFor(() => {
      expect(screen.getByText('Regulatory Scrutiny Overview')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /^Applications$/i }));
    expect(await screen.findByText('APP-2026-0105')).toBeInTheDocument();
    fireEvent.click(screen.getByText('APP-2026-0105'));

    await waitFor(() => {
      expect(screen.getAllByText(/Source Unavailable/i).length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText(/Sandbox Issuer/i).length).toBeGreaterThan(0);
  });

  it('4. hides all demo login shortcuts and credential displays when ENABLE_DEMO_MODE=false', async () => {
    simulateDemoModeDisabled = true;
    render(<App />);

    await waitFor(() => {
      expect(screen.getByText('Authorised Officer Sign In')).toBeInTheDocument();
    });

    // Wait a tick for fetchDemoStatus() effect to settle
    await new Promise((r) => setTimeout(r, 40));

    expect(
      screen.queryByRole('button', { name: /Development Demo Mode — Sample Evaluation Accounts/i })
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Synthetic Demo Passphrase/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/officer@authentix\.demo/i)).not.toBeInTheDocument();
    expect(screen.queryByText(DEMO_PASSWORD)).not.toBeInTheDocument();
    expect(demoAccountsFetchCount).toBe(0);

    // Standard sign-in form and credential validation remain active
    expect(screen.getByLabelText(/Official Email Address/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Password/i)).toBeInTheDocument();
  });

  it('5. supports Admin Rule Governance toggle, accessible Retry recovery, and Reports & SHA-256 Audit verification', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByLabelText(/Official Email Address/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/Official Email Address/i), {
      target: { value: 'admin@authentix.demo' },
    });
    fireEvent.change(screen.getByLabelText(/Password/i), {
      target: { value: DEMO_PASSWORD },
    });
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));

    await waitFor(() => {
      expect(screen.getByText('Regulatory Scrutiny Overview')).toBeInTheDocument();
    });

    // Simulate transient error on Regulatory Rules and verify accessible Retry recovery
    simulateRulesError = true;
    fireEvent.click(screen.getByRole('button', { name: /Regulatory Rules/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Unable to load validation rules/i);

    simulateRulesError = false;
    fireEvent.click(screen.getByRole('button', { name: /^Retry$/i }));

    expect(await screen.findByText('RULE-DOC-TYPE-MATCH')).toBeInTheDocument();

    // Toggle first rule deactivation and reactivation via Admin UI control
    const deactivateButtons = await screen.findAllByRole('button', { name: /^Deactivate Rule$/i });
    fireEvent.click(deactivateButtons[0]);
    expect(await screen.findByRole('status')).toHaveTextContent(/Deactivated/i);
    expect(screen.getByText('Disabled by Administrator')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Activate Rule$/i }));
    expect(await screen.findByRole('status')).toHaveTextContent(/Activated/i);

    // Navigate to Reports & Audit and verify hash-chain check + truthful SQLite/PostgreSQL runtime status
    fireEvent.click(screen.getByRole('button', { name: /Reports & Audit/i }));
    expect(await screen.findByText(/Validation Reports & Tamper-Evident Audit Trail/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Verify SHA-256 Chain Integrity/i }));
    expect(await screen.findByText(/Chain Verified: All/i)).toBeInTheDocument();
    expect(await screen.findByText(/reference DDL only/i)).toBeInTheDocument();
  });

  it('6. supports Infrastructure & Compliance review, In-App Alerts (IN_APP_ONLY), and Admin pre-validated Rule creation', async () => {
    render(<App />);

    await waitFor(() => {
      expect(screen.getByLabelText(/Official Email Address/i)).toBeInTheDocument();
    });

    fireEvent.change(screen.getByLabelText(/Official Email Address/i), {
      target: { value: 'admin@authentix.demo' },
    });
    fireEvent.change(screen.getByLabelText(/Password/i), {
      target: { value: DEMO_PASSWORD },
    });
    fireEvent.click(screen.getByRole('button', { name: /Sign In to Scrutiny Console/i }));

    await waitFor(() => {
      expect(screen.getByText('Regulatory Scrutiny Overview')).toBeInTheDocument();
    });

    // Open In-App Alerts panel and verify explicit IN_APP_ONLY notice (no email/SMS claimed)
    fireEvent.click(screen.getByRole('button', { name: /In-App Alerts/i }));
    expect(await screen.findByLabelText('In-App Regulatory Alerts')).toBeInTheDocument();
    expect(screen.getByText(/external email and SMS gateways are not configured/i)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText('Close alerts panel'));

    // Open APP-2026-0102 and inspect the Infrastructure & Compliance tab
    fireEvent.click(await screen.findByText('APP-2026-0102'));
    const complianceTab = await screen.findByRole('tab', { name: /Infrastructure & Compliance/i });
    fireEvent.click(complianceTab);

    expect(
      await screen.findByText(/Regulatory & Infrastructure Compliance Checklist/i)
    ).toBeInTheDocument();
    expect(screen.getAllByText(/LocalDeterministicVisualInspector/i).length).toBeGreaterThan(0);

    // Review first compliance requirement and save an officer observation
    const reviewBtns = await screen.findAllByRole('button', { name: /Review Requirement/i });
    fireEvent.click(reviewBtns[0]);
    fireEvent.change(screen.getByLabelText('Compliance officer observation'), {
      target: { value: 'UI compliance observation recorded by administrator.' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Save Compliance Assessment/i }));
    expect(
      await screen.findByText(/Persisted compliance requirement assessment/i)
    ).toBeInTheDocument();

    // Navigate to Regulatory Rules and verify pre-publication validation error + valid rule creation
    fireEvent.click(screen.getByRole('button', { name: /Regulatory Rules/i }));
    fireEvent.click(await screen.findByRole('button', { name: /Create Configurable Rule/i }));

    // Test invalid JSON config rejection
    fireEvent.change(screen.getByLabelText(/Rule Parameters \(JSON\)/i), {
      target: { value: '{broken_json' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Validate & Save Rule/i }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/syntactically invalid/i);

    // Fix JSON and save valid custom rule
    fireEvent.change(screen.getByLabelText(/Rule Code/i), {
      target: { value: 'RULE-UI-CUSTOM-FACULTY' },
    });
    fireEvent.change(screen.getByLabelText(/Rule Parameters \(JSON\)/i), {
      target: {
        value: JSON.stringify({ fieldName: 'total_faculty_count', minValue: 20, unit: 'faculty' }),
      },
    });
    fireEvent.click(screen.getByRole('button', { name: /Validate & Save Rule/i }));
    expect(await screen.findByRole('status')).toHaveTextContent(/Created and validated rule RULE-UI-CUSTOM-FACULTY/i);
    expect(await screen.findByText('RULE-UI-CUSTOM-FACULTY')).toBeInTheDocument();
  });
});


