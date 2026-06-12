import React, { useState, useEffect, useRef } from 'react';

const API = '/api';

const sourceColors = {
  abuseipdb: 'badge-red',
  ip_geolocation: 'badge-teal',
  shodan_internetdb: 'badge-amber',
  duckduckgo_search: 'badge-blue',
  rdap_whois: 'badge-purple',
  breach_lookup: 'badge-red',
  whatsmyname: 'badge-green',
  default: 'badge-blue',
};

const loadingSteps = [
  'Initializing OSINT collectors…',
  'Querying WhatsMyName database (500+ sites)…',
  'Running domain RDAP / WHOIS lookup…',
  'Performing DuckDuckGo correlation search…',
  'Checking AbuseIPDB reputation feeds…',
  'Running Shodan InternetDB port scan…',
  'Extracting secondary indicators…',
  'Normalizing and deduplicating observations…',
  'Running entity resolution pipeline…',
  'Computing correlation graph elements…',
  'Writing intelligence to Neo4j…',
  'Finalising case ledger entry…',
];

export default function App() {
  // Navigation & UI state
  const [activeTab, setActiveTab] = useState('graph');
  const [selType, setSelType] = useState('Username');
  const [targetVal, setTargetVal] = useState('');
  
  // Status and scanning
  const [statusMsg, setStatusMsg] = useState('Ready. Enter an indicator to begin OSINT collection.');
  const [statusMode, setStatusMode] = useState('idle');
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [scanProgress, setScanProgress] = useState(0);

  // Data cache
  const [intel, setIntel] = useState(null);
  const [sources, setSources] = useState([]);
  const [cases, setCases] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  
  // Search filters
  const [caseSearch, setCaseSearch] = useState('');
  const [sourcesSearch, setSourcesSearch] = useState('');
  
  // Node Click tooltip
  const [tooltip, setTooltip] = useState({ show: false, x: 0, y: 0, label: '', type: '', id: '' });
  const [graphStats, setGraphStats] = useState('No nodes');
  const [graphFilter, setGraphFilter] = useState('all');

  // DOM Refs
  const cyRef = useRef(null);
  const mapRef = useRef(null);
  const cyContainerRef = useRef(null);
  const mapContainerRef = useRef(null);
  const markersRef = useRef([]);

  // Fetch initial collections
  useEffect(() => {
    loadCases();
    loadAuditLog();
    loadGraphData();
  }, []);

  // Sync Leaflet map size on tab change
  useEffect(() => {
    if (activeTab === 'map' && mapRef.current) {
      setTimeout(() => {
        mapRef.current.invalidateSize();
      }, 100);
    }
    setTooltip({ show: false, x: 0, y: 0, label: '', type: '', id: '' });
  }, [activeTab]);

  // Cytoscape Init and Cleanup
  useEffect(() => {
    if (cyContainerRef.current) {
      const cyInstance = window.cytoscape({
        container: cyContainerRef.current,
        elements: [],
        style: [
          {
            selector: 'node',
            style: {
              'background-color': '#2a3d55',
              'border-width': 1.5,
              'border-color': '#3b5a7e',
              label: 'data(label)',
              color: '#e2ecf8',
              'font-size': '10px',
              'font-family': 'JetBrains Mono, monospace',
              'text-valign': 'bottom',
              'text-margin-y': '8px',
              'text-wrap': 'wrap',
              'text-max-width': '100px',
              width: 24,
              height: 24,
            },
          },
          {
            selector: "node[type='subject']",
            style: {
              'background-color': '#ff4d6d',
              width: 36,
              height: 36,
              'border-color': '#ff8099',
              'border-width': 2.5,
              'font-size': '11px',
              'font-weight': '700',
              'box-shadow': '0 0 20px rgba(255,77,109,0.5)',
            },
          },
          {
            selector: "node[type='identity_cluster']",
            style: {
              'background-color': '#f5a623',
              'border-color': '#ffea7a',
              'border-width': 2,
              width: 30,
              height: 30,
              'font-size': '11px',
              'font-weight': '700',
              'box-shadow': '0 0 15px rgba(245,166,35,0.5)',
            },
          },
          { selector: "node[type='username']", style: { 'background-color': '#1a6fff' } },

          { selector: "node[type='email']", style: { 'background-color': '#1fd693' } },
          { selector: "node[type='domain']", style: { 'background-color': '#f5a623' } },
          { selector: "node[type='phone']", style: { 'background-color': '#a78bfa' } },
          { selector: "node[type='ip']", style: { 'background-color': '#0c1118', 'border-color': '#f5a623', 'border-width': 2 } },
          { selector: "node[type='source']", style: { 'background-color': '#1e3050', width: 14, height: 14, 'font-size': '8px' } },
          {
            selector: 'edge',
            style: {
              width: 'mapData(confidence, 0, 1, 1, 4)',
              opacity: 'mapData(confidence, 0, 1, 0.3, 0.9)',
              'line-color': '#2e4560',
              'target-arrow-shape': 'triangle',
              'target-arrow-color': '#2e4560',
              'curve-style': 'bezier',
              label: 'data(label)',
              'font-size': '8px',
              color: '#4a6b8c',
            },
          },
          {
            selector: "edge[type='inferred']",
            style: {
              'line-style': 'dashed',
              'line-dash-pattern': [6, 4],
              'line-color': '#3a6080',
              'target-arrow-color': '#3a6080',
            },
          },
          { selector: '.filtered-out', style: { display: 'none' } },
          {
            selector: ':selected',
            style: {
              'border-color': '#3b9cff',
              'border-width': 3,
            },
          },
        ],
        layout: { name: 'cose', animate: true, animationDuration: 500, fit: true, padding: 40, nodeRepulsion: 4500 },
      });

      // Events
      cyInstance.on('tap', 'node', (evt) => {
        const node = evt.target;
        const renderedPos = evt.renderedPosition || evt.cyRenderedPosition;
        setTooltip({
          show: true,
          x: renderedPos.x + 16,
          y: renderedPos.y + 16,
          label: node.data('label') || '—',
          type: node.data('type') || '?',
          id: node.data('id') || '',
        });
      });

      cyInstance.on('tap', (evt) => {
        if (evt.target === cyInstance) {
          setTooltip({ show: false, x: 0, y: 0, label: '', type: '', id: '' });
        }
      });

      cyInstance.on('zoom pan', () => {
        setTooltip({ show: false, x: 0, y: 0, label: '', type: '', id: '' });
      });

      cyRef.current = cyInstance;

      return () => {
        cyInstance.destroy();
        cyRef.current = null;
      };
    }
  }, [activeTab]);

  // Leaflet Map Init and Cleanup
  useEffect(() => {
    if (activeTab === 'map' && mapContainerRef.current) {
      const leafletMap = window.L.map(mapContainerRef.current, { zoomControl: true }).setView([20, 78], 3);
      window.L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        className: 'map-tiles',
      }).addTo(leafletMap);

      mapRef.current = leafletMap;

      // Restore markers if active intelligence has geolocation
      if (intel) {
        plotGeo(intel, leafletMap);
      }

      return () => {
        leafletMap.remove();
        mapRef.current = null;
        markersRef.current = [];
      };
    }
  }, [activeTab, intel]);

  // Fetch API Helper
  async function apiFetch(url, options = {}) {
    const resp = await fetch(url, options);
    if (!resp.ok) {
      let detail = resp.statusText;
      try {
        const j = await resp.json();
        detail = j.detail || j.error || detail;
      } catch {}
      throw new Error(`HTTP ${resp.status}: ${detail}`);
    }
    return resp.json();
  }

  // Load Graph Data
  async function loadGraphData() {
    try {
      const elements = await apiFetch(`${API}/graph`);
      if (cyRef.current) {
        cyRef.current.elements().remove();
        if (elements && elements.length) {
          cyRef.current.add(elements);
          relayoutGraph();
        }
        applyGraphFilter(graphFilter);
        const nodes = cyRef.current.nodes().length;
        const edges = cyRef.current.edges().length;
        setGraphStats(`${nodes} nodes · ${edges} edges`);
      }
    } catch (e) {
      console.warn('Graph load failed:', e.message);
    }
  }

  // Re-layout Graph
  function relayoutGraph() {
    if (cyRef.current) {
      cyRef.current.layout({ name: 'cose', animate: true, animationDuration: 500, fit: true, padding: 40, nodeRepulsion: 4500 }).run();
    }
  }

  // Filter Graph Edges
  function applyGraphFilter(filterVal) {
    setGraphFilter(filterVal);
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.elements().removeClass('filtered-out');
    if (filterVal === 'raw') {
      cy.edges("[type != 'raw']").addClass('filtered-out');
    } else if (filterVal === 'inferred') {
      cy.edges("[type != 'inferred']").addClass('filtered-out');
    }
    cy.nodes().forEach((n) => {
      if (n.connectedEdges().filter((e) => !e.hasClass('filtered-out')).length === 0 && n.data('type') !== 'subject') {
        n.addClass('filtered-out');
      }
    });
  }

  // Load Past Cases
  async function loadCases() {
    try {
      const data = await apiFetch(`${API}/cases`);
      setCases(data || []);
    } catch (e) {
      console.warn('Cases load failed:', e);
    }
  }

  // Load Audit log
  async function loadAuditLog() {
    try {
      const entries = await apiFetch(`${API}/audit`);
      setAuditLogs(entries || []);
    } catch (e) {
      console.warn('Audit load failed:', e);
    }
  }

  // Plot coordinates on Leaflet Map
  function plotGeo(extracted, customMapInstance) {
    const lat = extracted.latitude;
    const lon = extracted.longitude;
    const activeMap = customMapInstance || mapRef.current;

    // Clear old markers
    markersRef.current.forEach((m) => m.remove());
    markersRef.current = [];

    if (lat && lon && activeMap) {
      const icon = window.L.divIcon({
        html: `<div style="width:14px;height:14px;border-radius:50%;background:#ff4d6d;border:2px solid #fff;box-shadow:0 0 10px rgba(255,77,109,0.6);"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7],
        className: '',
      });
      const marker = window.L.marker([lat, lon], { icon }).addTo(activeMap).bindPopup(`<b>${extracted.geo_country || extracted.scammer_alias}</b>`);
      markersRef.current.push(marker);
      activeMap.setView([lat, lon], 7);
      marker.openPopup();
    }
  }

  // Active Intel Scanning
  async function runInvestigation(e) {
    if (e) e.preventDefault();
    if (!targetVal.trim()) {
      setStatusMsg('⚠️ Enter an indicator value.');
      setStatusMode('warn');
      return;
    }

    setIsLoading(true);
    setScanProgress(0);
    setStatusMsg(`Launching OSINT scan for ${selType}: ${targetVal}`);
    setStatusMode('warn');

    // Simulate animated loading progress
    let currentProgress = 0;
    const progressTimer = setInterval(() => {
      currentProgress = Math.min(currentProgress + Math.random() * 8, 85);
      setScanProgress(currentProgress);
    }, 400);

    // Scan steps animation
    let stepIdx = 0;
    setLoadingStep(loadingSteps[0]);
    const stepTimer = setInterval(() => {
      stepIdx = Math.min(stepIdx + 1, loadingSteps.length - 1);
      setLoadingStep(loadingSteps[stepIdx]);
    }, 2500);

    try {
      const data = await apiFetch(`${API}/investigate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ selector: selType, value: targetVal }),
      });

      clearInterval(progressTimer);
      clearInterval(stepTimer);
      setScanProgress(100);

      const extracted = data.extracted_intelligence;
      setIntel(extracted);
      setSources(extracted.source_hits || []);

      // Reload databases
      await loadGraphData();
      await loadCases();
      await loadAuditLog();

      // Geolocation
      if (extracted.latitude && extracted.longitude) {
        if (activeTab !== 'map') {
          setActiveTab('map');
        } else {
          plotGeo(extracted);
        }
      } else {
        if (extracted.source_hits && extracted.source_hits.length > 0) {
          setActiveTab('sources');
        } else {
          setActiveTab('graph');
        }
      }

      setSelectedCaseId(data.case?.id || null);
      setStatusMsg(`✅ Scan complete. ${extracted.source_hits?.length || 0} evidence sources collected. State: ${extracted.observation_state || 'observed'}.`);
      setStatusMode('success');
    } catch (err) {
      clearInterval(progressTimer);
      clearInterval(stepTimer);
      setStatusMsg(`❌ Scan failed: ${err.message}`);
      setStatusMode('error');
    } finally {
      setIsLoading(false);
      setTimeout(() => setScanProgress(0), 1000);
    }
  }

  // Load a historic case card
  function loadCase(c) {
    setSelectedCaseId(c.id);
    setIntel(c);
    setSources(c.source_hits || []);
    setActiveTab('sources');
    
    // Auto geolocate case if maps exist
    if (c.latitude && c.longitude && activeTab === 'map') {
      plotGeo(c);
    }
  }

  // Clear UI workspace
  function clearAll() {
    if (cyRef.current) {
      cyRef.current.elements().remove();
    }
    setGraphStats('No nodes');
    setSources([]);
    setIntel(null);
    setTargetVal('');
    setSelectedCaseId(null);
    setStatusMsg('Workspace cleared. Ready for new scan.');
    setStatusMode('idle');
    setActiveTab('graph');
  }

  // Safe HTML values escape
  function esc(v) {
    return String(v ?? '');
  }

  // Filter lists
  const filteredCases = cases.filter(c =>
    JSON.stringify(c).toLowerCase().includes(caseSearch.toLowerCase())
  );
  
  const filteredSources = sources.filter(s =>
    JSON.stringify(s).toLowerCase().includes(sourcesSearch.toLowerCase())
  );

  return (
    <div className="app-shell">
      {/* Loading Overlay */}
      {isLoading && (
        <div id="loading-overlay" className="active">
          <div className="spinner"></div>
          <div>
            <div className="loading-text" style={{ fontWeight: 700 }}>Scanning {selType}: {targetVal}</div>
            <div className="loading-steps" style={{ marginTop: '8px' }}>{loadingStep}</div>
          </div>
        </div>
      )}

      {/* Animated Scan Progress Bar */}
      {scanProgress > 0 && (
        <div id="scan-progress" style={{ width: `${scanProgress}%`, transition: 'width 0.3s ease' }}></div>
      )}

      {/* Context tooltip for Cytoscape nodes */}
      {tooltip.show && (
        <div id="node-tooltip" style={{ display: 'block', left: tooltip.x, top: tooltip.y }}>
          <div style={{ fontWeight: 700, fontSize: '13px', marginBottom: '6px' }}>{tooltip.label}</div>
          <div className="badge badge-blue" style={{ marginBottom: '8px' }}>{tooltip.type}</div>
          <div className="text-dim" style={{ fontSize: '10px', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>{tooltip.id}</div>
        </div>
      )}

      {/* Top Bar Header */}
      <header className="topbar">
        <div className="topbar-brand">
          <div className="brand-icon">🔍</div>
          <div>
            <div className="brand-name">Looker OSINT</div>
            <div className="brand-sub">Cyber Intelligence Console — Law Enforcement</div>
          </div>
        </div>
        <div className="topbar-status">
          <div className="status-pill"><div className="dot dot-green"></div>OSINT Active</div>
          <div className="status-pill"><div className="dot dot-blue"></div>Neo4j Graph</div>
          <div className="status-pill"><div className="dot dot-amber"></div>Entity Resolution</div>
          <div className="status-pill" style={{ cursor: 'pointer' }} onClick={loadAuditLog}>
            <div className="dot dot-blue"></div>Audit Trail
          </div>
        </div>
      </header>

      {/* Main Grid Workspace */}
      <div className="main-grid">
        
        {/* Sidebar Controls */}
        <aside className="sidebar">
          {/* Query Lookup */}
          <div className="sidebar-section">
            <div className="section-label">Indicator Lookup</div>
            <div className="section-title" style={{ marginBottom: '14px' }}>Run OSINT Scan</div>

            <form id="query-form" onSubmit={runInvestigation}>
              <div className="field-wrap">
                <label className="field-label">Indicator Type</label>
                <select className="field" value={selType} onChange={(e) => setSelType(e.target.value)}>
                  <option value="Username">👤 Username / Handle</option>
                  <option value="Email">📧 Email Address</option>
                  <option value="Phone Number">📱 Phone Number</option>
                  <option value="Domain">🌐 Domain / URL</option>
                  <option value="IP Address">🖥️ IP Address</option>
                </select>
              </div>
              <div className="field-wrap">
                <label className="field-label">Target Value</label>
                <input
                  className="field"
                  type="text"
                  placeholder="e.g. johndoe, 192.168.1.1, phish.com"
                  autoComplete="off"
                  spellCheck="false"
                  value={targetVal}
                  onChange={(e) => setTargetVal(e.target.value)}
                />
              </div>
              <button className="btn btn-primary btn-full" type="submit" disabled={isLoading}>
                <span>🚀</span> Run Active Intelligence Scan
              </button>
              <div id="status-log" className={statusMode === 'success' ? 'log-success' : statusMode === 'warn' ? 'log-warn' : statusMode === 'error' ? 'log-error' : ''}>
                {statusMsg}
              </div>
            </form>
          </div>

          {/* Confidence Score */}
          {intel && (
            <div className="sidebar-section">
              <div className="section-label">Assessment</div>
              <div className="section-title mt-1">Confidence Score</div>
              <div className="confidence-bar-wrap mt-2">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="text-muted" style={{ fontSize: '11px', textTransform: 'capitalize' }}>
                    {intel.observation_state || 'inferred'}
                  </span>
                  <span style={{ fontSize: '14px', fontWeight: 700 }}>
                    {((intel.source_reliability || 0) * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="confidence-bar-bg">
                  <div className="confidence-bar-fill" style={{ width: `${(intel.source_reliability || 0) * 100}%` }}></div>
                </div>
              </div>
            </div>
          )}

          {/* Resolved Indicators Details */}
          {intel && (
            <div className="sidebar-section">
              <div className="section-label">Extracted Intelligence</div>
              <div className="section-title mt-1">Resolved Indicators</div>
              <div className="mt-2">
                <table className="indicator-table">
                  <tbody>
                    <tr>
                      <td>Alias</td>
                      <td>{esc(intel.scammer_alias)}</td>
                    </tr>
                    <tr>
                      <td>Observation</td>
                      <td>{esc(intel.observation_state)}</td>
                    </tr>
                    <tr>
                      <td>Reliability</td>
                      <td>{((intel.source_reliability || 0) * 100).toFixed(0)}%</td>
                    </tr>
                    <tr>
                      <td>Usernames</td>
                      <td>{(intel.raw_indicators?.username || []).join(', ') || '—'}</td>
                    </tr>
                    <tr>
                      <td>Emails</td>
                      <td>{(intel.raw_indicators?.email || []).join(', ') || '—'}</td>
                    </tr>
                    <tr>
                      <td>Phones</td>
                      <td>{(intel.raw_indicators?.phone || []).join(', ') || '—'}</td>
                    </tr>
                    <tr>
                      <td>Domains</td>
                      <td>{(intel.raw_indicators?.domain || []).join(', ') || '—'}</td>
                    </tr>
                    <tr>
                      <td>IP Addresses</td>
                      <td>{(intel.raw_indicators?.ip || []).join(', ') || '—'}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Bottom actions */}
          <div className="sidebar-section" style={{ marginTop: 'auto' }}>
            <button className="btn btn-ghost btn-full btn-sm" onClick={clearAll}>↺ Clear Workspace</button>
            <div style={{ marginTop: '10px', fontSize: '10px', color: 'var(--text-dim)', textAlign: 'center' }}>
              Looker v3.2 · Police Cyber Cell · Strictly Confidential
            </div>
          </div>
        </aside>

        {/* Content Tabs Area */}
        <div className="content-area">
          <div className="tab-bar">
            <button className={`tab-btn ${activeTab === 'graph' ? 'active' : ''}`} onClick={() => setActiveTab('graph')}>
              🕸️ Correlation Graph
            </button>
            <button className={`tab-btn ${activeTab === 'map' ? 'active' : ''}`} onClick={() => setActiveTab('map')}>
              🗺️ Geo Map
            </button>
            <button className={`tab-btn ${activeTab === 'cases' ? 'active' : ''}`} onClick={() => setActiveTab('cases')}>
              📁 Case Ledger
            </button>
            <button className={`tab-btn ${activeTab === 'sources' ? 'active' : ''}`} onClick={() => setActiveTab('sources')}>
              📋 Source Evidence
            </button>
            <button className={`tab-btn ${activeTab === 'audit' ? 'active' : ''}`} onClick={() => setActiveTab('audit')}>
              🛡️ Audit Log
            </button>
          </div>

          {/* Graph Tab */}
          <div className={`tab-panel ${activeTab === 'graph' ? 'active' : ''}`} id="tab-graph">
            <div className="graph-toolbar">
              <select className="field" value={graphFilter} onChange={(e) => applyGraphFilter(e.target.value)}>
                <option value="all">All Connections</option>
                <option value="raw">Observed Only</option>
                <option value="inferred">Inferred Only</option>
              </select>
              <button className="btn btn-ghost btn-sm" onClick={loadGraphData}>↺ Reload</button>
              <button className="btn btn-ghost btn-sm" onClick={() => cyRef.current && cyRef.current.fit()}>⊡ Fit View</button>
              <button className="btn btn-ghost btn-sm" onClick={relayoutGraph}>⟳ Re-layout</button>
              <span style={{ marginLeft: 'auto', fontSize: '11px', color: 'var(--text-dim)' }}>
                {graphStats}
              </span>
            </div>
            <div id="cy-canvas" ref={cyContainerRef}></div>
          </div>

          {/* Map Tab */}
          <div className={`tab-panel ${activeTab === 'map' ? 'active' : ''}`} id="tab-map">
            <div className="graph-toolbar">
              <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Geolocation intelligence from IP resolution</span>
              <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => mapRef.current && mapRef.current.setView([20, 78], 3)}>
                Reset View
              </button>
            </div>
            <div id="map-canvas" ref={mapContainerRef}></div>
          </div>

          {/* Cases Ledger Tab */}
          <div className={`tab-panel ${activeTab === 'cases' ? 'active' : ''}`} id="tab-cases">
            <div className="search-bar-wrap">
              <input
                className="field search-bar w-full"
                placeholder="🔍 Search cases by indicator, ID, state…"
                value={caseSearch}
                onChange={(e) => setCaseSearch(e.target.value)}
              />
            </div>
            <div className="cases-container">
              {filteredCases.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">📁</div>
                  <div>No matching cases.</div>
                </div>
              ) : (
                <div className="case-grid">
                  {filteredCases.map((c) => {
                    const state = c.observation_state || 'inferred';
                    const badgeClass = state === 'observed' ? 'badge-green' : state === 'unresolved' ? 'badge-red' : 'badge-amber';
                    const ts = c.created_at ? new Date(c.created_at).toLocaleString() : '—';
                    return (
                      <button key={c.id} className={`case-card ${c.id === selectedCaseId ? 'selected' : ''}`} onClick={() => loadCase(c)}>
                        <div className="flex items-center justify-between">
                          <span className="case-id mono">{c.id}</span>
                          <span className={`badge ${badgeClass}`}>{state}</span>
                        </div>
                        <div className="case-indicator">{c.indicator_type}: {c.indicator_value}</div>
                        <div className="case-meta">
                          <span className="case-time">{ts}</span>
                          <span className="text-dim" style={{ fontSize: '10px' }}>
                            {c.scammer_alias?.slice(0, 18)}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Source Evidence Tab */}
          <div className={`tab-panel ${activeTab === 'sources' ? 'active' : ''}`} id="tab-sources">
            <div className="search-bar-wrap">
              <input
                className="field search-bar w-full"
                placeholder="🔍 Filter source evidence…"
                value={sourcesSearch}
                onChange={(e) => setSourcesSearch(e.target.value)}
              />
            </div>
            <div className="sources-container">
              {filteredSources.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">📋</div>
                  <div>No source evidence collected yet.</div>
                </div>
              ) : (
                <div className="sources-grid">
                  {filteredSources.map((h, i) => {
                    const src = (h.source || '').toLowerCase();
                    let badgeClass = 'badge-blue';
                    for (const [key, cls] of Object.entries(sourceColors)) {
                      if (src.includes(key)) {
                        badgeClass = cls;
                        break;
                      }
                    }
                    const conf = h.confidence ? `${(h.confidence * 100).toFixed(0)}%` : '';
                    const url = h.url || '';
                    return (
                      <div key={i} className="source-card">
                        <span className={`badge ${badgeClass} source-badge`}>{h.source || 'unknown'}</span>
                        <div className="source-title">{h.title?.replace(/^\[.*?\]\s*/, '')}</div>
                        <div className="source-snippet">{h.snippet || '—'}</div>
                        {url && (
                          <a className="source-url" href={url} target="_blank" rel="noopener noreferrer">
                            🔗 {url}
                          </a>
                        )}
                        {conf && (
                          <div className="source-confidence">
                            <span className="text-dim">Confidence:</span>{' '}
                            <span style={{ color: 'var(--green)' }}>{conf}</span>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Immutable Audit Log Tab */}
          <div className={`tab-panel ${activeTab === 'audit' ? 'active' : ''}`} id="tab-audit">
            <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', display: 'flex', gap: '8px', alignItems: 'center', flexShrink: 0 }}>
              <button className="btn btn-ghost btn-sm" onClick={loadAuditLog}>↺ Refresh</button>
              <span className="text-dim" style={{ fontSize: '11px' }}>Immutable operational audit trail</span>
            </div>
            <div className="audit-container">
              {auditLogs.length === 0 ? (
                <div className="empty-state">
                  <div className="empty-icon">🛡️</div>
                  <div>Audit log is empty.</div>
                </div>
              ) : (
                [...auditLogs].reverse().slice(0, 200).map((e, i) => {
                  const ts = e.timestamp ? new Date(e.timestamp).toLocaleString() : '—';
                  const type = e.event_type || 'event';
                  const isCase = type.includes('case');
                  const isInvest = type.includes('investigation');
                  let cls = '';
                  if (isCase) cls = 'audit-case';
                  if (isInvest) cls = 'audit-invest';
                  const payload = e.payload || {};
                  const detail = payload.case_id
                    ? `${payload.case_id} · ${payload.selector}: ${payload.value}`
                    : (payload.indicator_value ? `${payload.indicator_type}: ${payload.indicator_value}` : '');
                  return (
                    <div key={i} className={`audit-entry ${cls}`}>
                      <div className="flex items-center justify-between">
                        <span className="audit-type">{type.replace(/_/g, ' ').toUpperCase()}</span>
                        <span className="audit-time">{ts}</span>
                      </div>
                      {detail && (
                        <div className="text-muted" style={{ fontSize: '10px', marginTop: '3px' }}>
                          {detail}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
