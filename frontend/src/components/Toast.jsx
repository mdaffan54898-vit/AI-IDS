import React, { useEffect } from 'react';

const Toast = ({ id, type = 'info', message, onClose, duration = 4000 }) => {
  useEffect(() => {
    const t = setTimeout(() => onClose && onClose(id), duration);
    return () => clearTimeout(t);
  }, [id, onClose, duration]);

  const bg = type === 'success' ? 'bg-green-500' : type === 'error' ? 'bg-red-500' : 'bg-gray-700';

  return (
    <div className={`text-white px-4 py-2 rounded shadow ${bg}`}>
      {message}
    </div>
  );
};

export default Toast;
