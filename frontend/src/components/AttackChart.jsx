import React from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

const AttackChart = ({ data }) => {
  if (!data || data.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <p className="mb-2 font-semibold">No attack data yet</p>
        <p className="text-sm">Waiting for real-time alerts to populate the chart.</p>
      </div>
    );
  }

  const chartData = {
    labels: data.map(d => d.time),
    datasets: [
      {
        label: 'Attacks Over Time',
        data: data.map(d => d.count),
        borderColor: 'rgb(255, 99, 132)',
        backgroundColor: 'rgba(255, 99, 132, 0.5)',
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
        text: 'Attack Types Over Time',
      },
    },
  };

  return <Line data={chartData} options={options} />;
};

export default AttackChart;