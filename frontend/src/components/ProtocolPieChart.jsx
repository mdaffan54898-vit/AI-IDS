import React from 'react';
import { Pie } from 'react-chartjs-2';
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

const ProtocolPieChart = ({ data }) => {
  const keys = Object.keys(data || {});
  if (!keys.length) {
    return (
      <div className="text-center py-12 text-gray-500">
        <p className="mb-2 font-semibold">No protocol data yet</p>
        <p className="text-sm">Protocol distribution will appear as alerts arrive.</p>
      </div>
    );
  }

  const chartData = {
    labels: keys,
    datasets: [
      {
        data: keys.map(k => data[k]),
        backgroundColor: [
          'rgba(255, 99, 132, 0.6)',
          'rgba(54, 162, 235, 0.6)',
          'rgba(255, 206, 86, 0.6)',
          'rgba(75, 192, 192, 0.6)',
          'rgba(153, 102, 255, 0.6)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: true,
        text: 'Protocol Distribution',
      },
    },
  };

  return <Pie data={chartData} options={options} />;
};

export default ProtocolPieChart;