import React from 'react';

const AlertModal = ({ alert, isOpen, onClose, onAcknowledge, onBlockIP }) => {
  if (!isOpen || !alert) return null;

  return (
    <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
      <div className="relative top-20 mx-auto p-5 border w-11/12 md:w-3/4 lg:w-1/2 shadow-lg rounded-md bg-white">
        <div className="mt-3">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Alert Details</h3>
          <div className="space-y-4">
            <div><strong>Timestamp:</strong> {alert.timestamp}</div>
            <div><strong>Source IP:</strong> {alert.src_ip}</div>
            <div><strong>Destination IP:</strong> {alert.dst_ip}</div>
            <div><strong>Protocol:</strong> {alert.protocol}</div>
            <div><strong>Attack Type:</strong> <span className="text-red-600 font-semibold">{alert.attack_type}</span></div>
            <div><strong>Bytes Sent:</strong> {alert.bytes_sent}</div>
            <div><strong>AI Analysis:</strong> {alert.gemini_explanation}</div>
            <div><strong>Recommended Action:</strong> {alert.gemini_recommendation}</div>
            {/* Add more raw packet info if available */}
          </div>
          <div className="flex justify-end space-x-4 mt-6">
            <button onClick={onClose} className="px-4 py-2 bg-gray-300 text-gray-800 rounded hover:bg-gray-400">Close</button>
            <button onClick={() => onAcknowledge(alert.id)} className="px-4 py-2 bg-indigo-500 text-white rounded hover:bg-indigo-600">Acknowledge</button>
            <button onClick={() => onBlockIP(alert.src_ip)} className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600">Block IP</button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AlertModal;