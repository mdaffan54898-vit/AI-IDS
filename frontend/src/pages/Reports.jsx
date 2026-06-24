import React, { useState } from 'react';
import { api, endpoints } from '../api/api';

const Reports = () => {
  const [filters, setFilters] = useState({
    startDate: '',
    endDate: '',
    attackType: '',
    srcIP: '',
    dstIP: '',
  });
  const [reports, setReports] = useState([]);

  const handleFilterChange = (e) => {
    setFilters({ ...filters, [e.target.name]: e.target.value });
  };

  const generateReport = () => {
    api.get(endpoints.getReports, { params: filters }).then(res => setReports(res.data));
  };

  const downloadCSV = () => {
    api.get(endpoints.downloadReport, { params: { ...filters, format: 'csv' }, responseType: 'blob' })
      .then(res => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', 'report.csv');
        document.body.appendChild(link);
        link.click();
      });
  };

  const downloadPDF = () => {
    api.get(endpoints.downloadReport, { params: { ...filters, format: 'pdf' }, responseType: 'blob' })
      .then(res => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', 'report.pdf');
        document.body.appendChild(link);
        link.click();
      });
  };

  return (
    <div className="p-6 bg-gray-100 min-h-screen">
      <h1 className="text-3xl font-bold mb-6">Reports</h1>

      {/* Filters */}
      <div className="bg-white p-6 rounded-lg shadow-md mb-6">
        <h2 className="text-xl font-semibold mb-4">Generate Report</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <input type="date" name="startDate" value={filters.startDate} onChange={handleFilterChange} className="p-2 border rounded" />
          <input type="date" name="endDate" value={filters.endDate} onChange={handleFilterChange} className="p-2 border rounded" />
          <input type="text" name="attackType" placeholder="Attack Type" value={filters.attackType} onChange={handleFilterChange} className="p-2 border rounded" />
          <input type="text" name="srcIP" placeholder="Source IP" value={filters.srcIP} onChange={handleFilterChange} className="p-2 border rounded" />
          <input type="text" name="dstIP" placeholder="Destination IP" value={filters.dstIP} onChange={handleFilterChange} className="p-2 border rounded" />
        </div>
        <button onClick={generateReport} className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">Generate Report</button>
      </div>

      {/* Report Display */}
      {reports.length > 0 && (
        <div className="bg-white p-6 rounded-lg shadow-md mb-6">
          <h2 className="text-xl font-semibold mb-4">Report Results</h2>
          <div className="mb-4">
            <button onClick={downloadCSV} className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 mr-2">Download CSV</button>
            <button onClick={downloadPDF} className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">Download PDF</button>
          </div>
          {/* Display summarized report, charts, etc. */}
          <pre>{JSON.stringify(reports, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default Reports;