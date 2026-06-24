import React, { useState } from 'react';

const AlertsTable = ({ alerts, onAcknowledge, onBlockIP, onViewDetails }) => {
  const [sortConfig, setSortConfig] = useState({ key: 'timestamp', direction: 'desc' });

  const sortedAlerts = [...alerts].sort((a, b) => {
    if (a[sortConfig.key] < b[sortConfig.key]) {
      return sortConfig.direction === 'asc' ? -1 : 1;
    }
    if (a[sortConfig.key] > b[sortConfig.key]) {
      return sortConfig.direction === 'asc' ? 1 : -1;
    }
    return 0;
  });

  const handleSort = (key) => {
    setSortConfig({
      key,
      direction: sortConfig.key === key && sortConfig.direction === 'asc' ? 'desc' : 'asc',
    });
  };

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full bg-white shadow-md rounded-lg">
        <thead className="bg-gray-50 sticky top-0">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onClick={() => handleSort('timestamp')}>
              Timestamp
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onClick={() => handleSort('src_ip')}>
              Src IP
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onClick={() => handleSort('dst_ip')}>
              Dst IP
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onClick={() => handleSort('attack_type')}>
              Attack Type
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              AI Analysis
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Recommended Action
            </th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="bg-white divide-y divide-gray-200">
          {sortedAlerts.map((alert, index) => {
            // Accept severity in multiple possible fields
            const severity = alert.severity || alert.sev || alert.gemini_severity || 'Unknown';
            const SEVERITY_COLOR = {
              Critical: '#FF0000',
              High: '#FF8C00',
              Medium: '#FFD700',
              Low: '#32CD32',
              Unknown: '#E5E7EB'
            };
            const color = alert.color || SEVERITY_COLOR[severity] || SEVERITY_COLOR.Unknown;
            const rowStyle = { borderLeft: `4px solid ${color}` };
            const isAcknowledged = !!alert.acknowledged;
            const isBlocked = !!alert.blocked;

            return (
              <tr
                key={index}
                style={rowStyle}
                className={`${index % 2 === 0 ? 'bg-white' : 'bg-gray-50'} ${isBlocked ? 'line-through opacity-60' : ''}`}
                onClick={() => onViewDetails(alert)}
              >
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{alert.displayTimestamp || alert.timestamp}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{alert.src_ip}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{alert.dst_ip}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-semibold flex items-center">
                  <span className="mr-2 text-red-600">{alert.attack_type}</span>
                  {severity && severity !== 'Unknown' && (
                    <span style={{ backgroundColor: color, color: '#ffffff' }} className="text-xs px-2 py-1 rounded-full font-medium">
                      {severity}
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">{alert.gemini_explanation}</td>
                <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">{alert.gemini_recommendation}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  {isAcknowledged ? (
                    <span className="inline-block mr-3 px-3 py-1 rounded-full bg-green-500 text-white text-xs font-semibold">Acknowledged</span>
                  ) : (
                    <button onClick={(e) => { e.stopPropagation(); onAcknowledge(alert.id); }} className="text-indigo-600 hover:text-indigo-900 mr-2">Acknowledge</button>
                  )}

                  <button
                    onClick={(e) => { e.stopPropagation(); onBlockIP(alert.src_ip); }}
                    className={`mr-2 ${isBlocked ? 'text-gray-400 cursor-not-allowed' : 'text-red-600 hover:text-red-900'}`}
                    disabled={isBlocked}
                  >
                    {isBlocked ? 'Blocked' : 'Block IP'}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default AlertsTable;