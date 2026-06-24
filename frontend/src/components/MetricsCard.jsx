import React from 'react';

const MetricsCard = ({ title, value, color = 'blue' }) => {
  return (
    <div className={`bg-white p-6 rounded-lg shadow-md hover:shadow-lg transition-shadow border-l-4 border-${color}-500`}>
      <h3 className="text-lg font-semibold text-gray-700">{title}</h3>
      <p className={`text-3xl font-bold text-${color}-600`}>{value}</p>
    </div>
  );
};

export default MetricsCard;