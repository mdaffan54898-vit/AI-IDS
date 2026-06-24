import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import io from 'socket.io-client';
import MetricsCard from '../components/MetricsCard';
import AlertsTable from '../components/AlertsTable';
import AlertModal from '../components/AlertModal';
import AttackChart from '../components/AttackChart';
import ProtocolPieChart from '../components/ProtocolPieChart';
import ConfirmModal from '../components/ConfirmModal';
import InterfaceSelector from '../components/InterfaceSelector';
import Toast from '../components/Toast';
import { api, endpoints, setApiKey } from '../api/api';

const Dashboard = () => {
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [metrics, setMetrics] = useState({ totalPackets: 0, attacks: 0, normal: 0, blockedIPs: 0 });
  const [idsStatus, setIdsStatus] = useState({ running: false, pid: null });
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [isActionPending, setIsActionPending] = useState(false);
  const [isStopModalOpen, setIsStopModalOpen] = useState(false);
  const [selectedInterface, setSelectedInterface] = useState('Wi-Fi');
  const [toasts, setToasts] = useState([]);
  const [interfaceOptions, setInterfaceOptions] = useState([]);
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [chartData, setChartData] = useState({ attacksOverTime: [], protocolDist: {} });
  const [timeframe, setTimeframe] = useState('24'); // default recent 24 hours ('1','6','24','all')
  const pollerRef = useRef(null);

  // Helpers
  const formatTimestamp = (ts) => {
    try {
      const d = new Date(ts);
      // Format: DD-MM-YY hh:mm AM/PM
      const day = String(d.getDate()).padStart(2, '0');
      const month = String(d.getMonth() + 1).padStart(2, '0');
      const year = String(d.getFullYear()).slice(-2);
      let hours = d.getHours();
      const minutes = String(d.getMinutes()).padStart(2, '0');
      const ampm = hours >= 12 ? 'PM' : 'AM';
      hours = hours % 12;
      if (hours === 0) hours = 12;
      const hh = String(hours).padStart(2, '0');
      return `${day}-${month}-${year} ${hh}:${minutes} ${ampm}`;
    } catch (e) {
      return ts;
    }
  };

  const normalizeAlert = useCallback((a) => {
    // Accept both backend shape and direct websocket payload
    return {
      id: a.id || (a._id || a._id?.$oid) || String(a.timestamp) || Math.random().toString(36).slice(2, 9),
      timestamp: a.timestamp || a.time || a.created_at || a.ts || '',
      displayTimestamp: formatTimestamp(a.timestamp || a.time || a.created_at || a.ts || ''),
      src_ip: a.src_ip || a.src || a.source || (a.features && a.features[0] && a.features[0].src_ip) || 'unknown',
      dst_ip: a.dst_ip || a.dst || a.dest || (a.features && a.features[0] && a.features[0].dst_ip) || 'unknown',
      attack_type: a.attack_type || a.type || (a.prediction && a.prediction.name) || (a.predictions && a.predictions[0]) || 'Unknown',
      gemini_explanation: a.gemini_explanation || a.explanation || (a.explanation && String(a.explanation)) || '',
      gemini_recommendation: a.gemini_recommendation || a.recommendation || a.recommend || '',
      // Gemini produced fields
  severity: a.severity || a.gemini_severity || a.level || null,
      color: a.color || a.severity_color || a.gemini_color || null,
      protocol: a.protocol || (a.features && a.features[0] && a.features[0].protocol) || 'unknown',
      bytes_sent: a.bytes_sent || a.sbytes || 0,
      acknowledged: !!a.acknowledged,
    };
  }, []);

  const computeChartData = (alertList) => {
    // Attacks over time (group by minute)
    const byTime = {};
    const proto = {};
    alertList.forEach((al) => {
      const t = new Date(al.timestamp || Date.now());
      // group key: YYYY-MM-DD HH:MM
      const key = `${t.getFullYear()}-${String(t.getMonth()+1).padStart(2,'0')}-${String(t.getDate()).padStart(2,'0')} ${String(t.getHours()).padStart(2,'0')}:${String(t.getMinutes()).padStart(2,'0')}`;
      byTime[key] = (byTime[key] || 0) + 1;
      const p = (al.protocol || 'unknown').toUpperCase();
      proto[p] = (proto[p] || 0) + 1;
    });

    const attacksOverTime = Object.keys(byTime).sort().map(k => ({ time: k, count: byTime[k] }));
    return { attacksOverTime, protocolDist: proto };
  };

  // Fetch initial data (timeframe controlled by user dropdown)
  const { data: initialAlerts } = useQuery({
    queryKey: ['alerts', 'recent', timeframe],
    queryFn: () => {
      const params = {};
      if (timeframe !== 'all') params.recent_hours = Number(timeframe);
      return api.get(endpoints.getAlerts, { params }).then(res => res.data);
    }
  });
  const { data: initialMetrics } = useQuery({ queryKey: ['metrics'], queryFn: () => api.get(endpoints.getMetrics).then(res => res.data) });

  useEffect(() => {
    if (initialAlerts) {
      const normalized = initialAlerts.map(normalizeAlert);
      setAlerts(normalized);
      const cd = computeChartData(normalized);
      setChartData(cd);
    }
    if (initialMetrics) setMetrics(initialMetrics);
    // fetch IDS status
    api.get(endpoints.getIDSStatus).then(res => {
      if (res && res.data) setIdsStatus(res.data);
    }).catch(() => {});
  }, [initialAlerts, initialMetrics, normalizeAlert]);

  // WebSocket connection
  useEffect(() => {
    const socket = io('ws://localhost:8000', {
      transports: ['websocket'],
      path: '/socket.io',
      reconnection: true,
      timeout: 20000,
    });

    socket.on('connect', () => {
      console.log('✅ Socket connected:', socket.id);
    });

    socket.on('connect_error', (err) => {
      console.error('❌ Socket connection error:', err && err.message ? err.message : err);
    });

    socket.on('new_alert', (alert) => {
      const n = normalizeAlert(alert);
      setAlerts(prev => {
        const next = [n, ...prev];
        const cd = computeChartData(next);
        setChartData(cd);
        return next;
      });
      setMetrics(prev => ({
        ...prev,
        attacks: prev.attacks + 1,
        totalPackets: prev.totalPackets + 1,
      }));
      // Update charts accordingly
      // Chart data updated by computeChartData above
    });

    return () => socket.disconnect();
  }, [normalizeAlert]);

  const handleStartIDS = () => {
    setIsActionPending(true);
    api.post(endpoints.startIDS, { interface: selectedInterface, packets: 0 })
      .then(res => {
        if (res && res.data) {
          setIdsStatus(res.data);
          // show success toast
          const id = Math.random().toString(36).slice(2, 8);
          setToasts(prev => [...prev, { id, type: 'success', message: `IDS started (pid ${res.data.pid})` }]);
          // Poll for status to confirm it's running
          setTimeout(() => {
            api.get(endpoints.getIDSStatus).then(statusRes => {
              if (statusRes && statusRes.data) setIdsStatus(statusRes.data);
            });
          }, 2000);
        }
      })
      .catch(err => {
        const id = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id, type: 'error', message: `Failed to start IDS: ${err?.response?.data || err.message}` }]);
      })
      .finally(() => setIsActionPending(false));
  };

  const handleStopIDS = () => {
    // Open confirm modal
    setIsStopModalOpen(true);
  };

  const confirmStopIDS = () => {
    setIsStopModalOpen(false);
    setIsActionPending(true);
    api.post(endpoints.stopIDS)
      .then(res => {
        if (res && res.data) setIdsStatus(res.data);
        const id = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id, type: 'success', message: `IDS stopped (pid ${res.data.pid || 'n/a'})` }]);
      })
      .catch(err => {
        const id = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id, type: 'error', message: `Failed to stop IDS: ${err?.response?.data || err.message}` }]);
      })
      .finally(() => setIsActionPending(false));
  };

  // Poll for IDS status every 15 seconds to keep UI in sync
  useEffect(() => {
    const fetchStatus = () => {
      api.get(endpoints.getIDSStatus).then(res => {
        if (res && res.data) setIdsStatus(res.data);
      }).catch(() => {});
    };
    // initial fetch
    fetchStatus();
    pollerRef.current = setInterval(fetchStatus, 15000);
    return () => {
      if (pollerRef.current) clearInterval(pollerRef.current);
    };
  }, []);

  // Fetch available network interfaces once on mount (with loading state)
  useEffect(() => {
    setInterfacesLoading(true);
    api.get(endpoints.getInterfaces).then(res => {
      if (res && res.data && Array.isArray(res.data.interfaces) && res.data.interfaces.length) {
        setInterfaceOptions(res.data.interfaces);
        setSelectedInterface(prev => {
          // prev is a string name; interfaces are objects with name
          const names = res.data.interfaces.map(i => i.name);
          return names.includes(prev) ? prev : names[0];
        });
      }
    }).catch(() => {
      // leave empty options on error
    }).finally(() => setInterfacesLoading(false));
  }, []);

  // Persist selected interface to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('ai_ids_last_interface', selectedInterface);
    } catch (e) {}
  }, [selectedInterface]);

  // Load persisted interface on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('ai_ids_last_interface');
      if (saved) setSelectedInterface(saved);
    } catch (e) {}
  }, []);

  const handleAcknowledge = (id) => {
    api.post(endpoints.acknowledgeAlert(id))
      .then(() => {
        setAlerts(prev => prev.map(a => a.id === id ? { ...a, acknowledged: true } : a));
        const tid = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id: tid, type: 'success', message: 'Alert acknowledged' }]);
      })
      .catch(err => {
        const tid = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id: tid, type: 'error', message: `Failed to acknowledge: ${err?.response?.data || err.message}` }]);
      });
  };

  const handleBlockIP = (ip) => {
    api.post(endpoints.blockIP(ip))
      .then(() => {
        // mark matching alerts as blocked locally
        setAlerts(prev => prev.map(a => a.src_ip === ip ? { ...a, blocked: true } : a));
        setMetrics(prev => ({ ...prev, blockedIPs: (prev.blockedIPs || 0) + 1 }));
        const tid = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id: tid, type: 'success', message: `The ${ip} is Blocked Successfully` }]);
      })
      .catch(err => {
        const tid = Math.random().toString(36).slice(2, 8);
        setToasts(prev => [...prev, { id: tid, type: 'error', message: `Failed to block IP: ${err?.response?.data || err.message}` }]);
      });
  };

  // Removed generate-rule support from UI

  const handleViewDetails = (alert) => {
    setSelectedAlert(alert);
    setIsModalOpen(true);
  };

  return (
    <div className="p-6 bg-gray-100 min-h-screen">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">AI IDS Dashboard</h1>
          <div className="space-x-4 flex items-center">
            <div className="mr-4">
              <span className={`px-3 py-1 rounded-full text-white ${idsStatus.running ? 'bg-green-600' : 'bg-gray-500'}`}>
                {idsStatus.running ? `Running (pid ${idsStatus.pid || 'n/a'})` : 'Stopped'}
              </span>
            </div>
            <div className="space-x-2">
                <button disabled={isActionPending} onClick={handleStartIDS} className="bg-green-500 disabled:opacity-50 text-white px-4 py-2 rounded hover:bg-green-600">Start IDS</button>
                <button disabled={isActionPending || !idsStatus.running} onClick={handleStopIDS} className="bg-red-500 disabled:opacity-50 text-white px-4 py-2 rounded hover:bg-red-600">Stop IDS</button>
            </div>
              <div className="ml-6 flex items-center space-x-3">
                <InterfaceSelector value={selectedInterface} onChange={setSelectedInterface} options={interfaceOptions} loading={interfacesLoading} />
              </div>
              <div className="ml-4">
                <label className="text-sm text-gray-600 mr-2">Timeframe:</label>
                <select value={timeframe} onChange={e => setTimeframe(e.target.value)} className="border px-2 py-1 rounded">
                  <option value="1">Last 1h</option>
                  <option value="6">Last 6h</option>
                  <option value="24">Last 24h</option>
                  <option value="all">All</option>
                </select>
              </div>
              <div className="ml-4 flex items-center">
              <input
                type="text"
                placeholder="API Key (optional)"
                value={apiKeyInput}
                onChange={e => setApiKeyInput(e.target.value)}
                className="border px-2 py-1 rounded mr-2"
              />
              <button onClick={() => { setApiKey(apiKeyInput); alert('API key saved to browser storage'); }} className="bg-blue-500 text-white px-3 py-1 rounded">Save Key</button>
            </div>
          </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        <MetricsCard title="Total Packets Captured" value={metrics.totalPackets} color="blue" />
        <MetricsCard title="Attacks Detected" value={metrics.attacks} color="red" />
        <MetricsCard title="Normal Packets" value={metrics.normal} color="green" />
        <MetricsCard title="Blocked IPs" value={metrics.blockedIPs} color="yellow" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <AttackChart data={chartData.attacksOverTime} />
        </div>
        <div className="bg-white p-6 rounded-lg shadow-md">
          <ProtocolPieChart data={chartData.protocolDist} />
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Recent Alerts</h2>
        <AlertsTable
          alerts={alerts}
          onAcknowledge={handleAcknowledge}
          onBlockIP={handleBlockIP}
          onViewDetails={handleViewDetails}
        />
      </div>

      {/* Alert Modal */}
      <AlertModal
        alert={selectedAlert}
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onAcknowledge={handleAcknowledge}
        onBlockIP={handleBlockIP}
      />

      <ConfirmModal
        isOpen={isStopModalOpen}
        title="Stop IDS"
        message="Stop the IDS process? This will attempt a graceful shutdown."
        onConfirm={confirmStopIDS}
        onCancel={() => setIsStopModalOpen(false)}
        confirmText="Stop"
        cancelText="Cancel"
      />

      {/* Toast stack */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        {toasts.map(t => (
          <Toast key={t.id} id={t.id} type={t.type} message={t.message} onClose={(id) => setToasts(prev => prev.filter(x => x.id !== id))} />
        ))}
      </div>
    </div>
  );
};

export default Dashboard;