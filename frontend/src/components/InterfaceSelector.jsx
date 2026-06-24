import React from 'react';

// Helpers to detect MAC and link-local addresses
const isMac = (s) => /^[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$/.test(s);
const isLinkLocalIPv6 = (s) => /^fe80:/i.test(s);
const isLinkLocalIPv4 = (s) => /^169\.254\./.test(s);
const isIPv4 = (s) => /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(s);

// options: [{ name: string, addrs: [ip1, ip2] }]
const InterfaceSelector = ({ value, onChange, options = [], loading = false }) => {
  if (loading) {
    return (
      <div className="flex items-center">
        <svg className="animate-spin h-5 w-5 text-gray-600 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path>
        </svg>
        <span className="text-sm text-gray-700">Loading interfaces...</span>
      </div>
    );
  }
  if (!options || options.length === 0) {
    return <div className="text-sm text-gray-600">No interfaces found</div>;
  }
  const renderLabel = (opt) => {
    if (!opt || !opt.addrs || !opt.addrs.length) return opt.name;
    // filter out MACs and link-local addresses
    const publicAddrs = opt.addrs.filter(a => !!a && !isMac(a) && !isLinkLocalIPv6(a) && !isLinkLocalIPv4(a));
    // prefer first IPv4
    const primary = publicAddrs.find(a => isIPv4(a)) || publicAddrs[0] || opt.addrs[0];
    return `${opt.name}${primary ? ` (${primary})` : ''}`;
  };

  return (
    <select value={value} onChange={e => onChange(e.target.value)} className="border px-2 py-1 rounded" title={options.length ? options.find(o => o.name === value)?.addrs?.join('\n') : ''}>
      {options.map(opt => {
        const label = renderLabel(opt);
        return <option key={opt.name} value={opt.name}>{label}</option>;
      })}
    </select>
  );
};

export default InterfaceSelector;
