import React from 'react';

const ConfirmModal = ({ isOpen, title = 'Confirm', message, onConfirm, onCancel, confirmText = 'OK', cancelText = 'Cancel' }) => {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 flex items-center justify-center bg-black bg-opacity-40 z-50">
      <div className="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
        <h3 className="text-lg font-semibold mb-4">{title}</h3>
        <p className="mb-6 text-gray-700">{message}</p>
        <div className="flex justify-end space-x-3">
          <button onClick={onCancel} className="px-4 py-2 rounded bg-gray-200">{cancelText}</button>
          <button onClick={onConfirm} className="px-4 py-2 rounded bg-red-600 text-white">{confirmText}</button>
        </div>
      </div>
    </div>
  );
};

export default ConfirmModal;
