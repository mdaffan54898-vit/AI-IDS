import React, { useState, useEffect } from 'react';
import { api, endpoints } from '../api/api';

const Settings = () => {
  const [settings, setSettings] = useState({
    twilio_sid: '',
    twilio_token: '',
    twilio_phone: '',
    whatsapp_number: '',
    gemini_key: '',
    model: 'multi-class',
    alert_threshold: 10,
    interface: 'Wi-Fi',
    num_packets: 100,
  });

  useEffect(() => {
    api.get(endpoints.getSettings).then(res => setSettings(res.data));
  }, []);

  const handleChange = (e) => {
    setSettings({ ...settings, [e.target.name]: e.target.value });
  };

  const saveSettings = () => {
    api.post(endpoints.updateSettings, settings).then(() => alert('Settings saved!'));
  };

  return (
    <div className="p-6 bg-gray-100 min-h-screen">
      <h1 className="text-3xl font-bold mb-6">Settings</h1>

      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-semibold mb-4">Configuration</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-700">Twilio SID</label>
            <input type="text" name="twilio_sid" value={settings.twilio_sid} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Twilio Token</label>
            <input type="password" name="twilio_token" value={settings.twilio_token} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Twilio Phone Number</label>
            <input type="text" name="twilio_phone" value={settings.twilio_phone} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">WhatsApp Number</label>
            <input type="text" name="whatsapp_number" value={settings.whatsapp_number} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Gemini API Key</label>
            <input type="password" name="gemini_key" value={settings.gemini_key} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Model Selection</label>
            <select name="model" value={settings.model} onChange={handleChange} className="mt-1 p-2 border rounded w-full">
              <option value="binary">Binary</option>
              <option value="multi-class">Multi-class</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Alert Threshold</label>
            <input type="number" name="alert_threshold" value={settings.alert_threshold} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Network Interface</label>
            <input type="text" name="interface" value={settings.interface} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Packets per Capture</label>
            <input type="number" name="num_packets" value={settings.num_packets} onChange={handleChange} className="mt-1 p-2 border rounded w-full" />
          </div>
        </div>

        <button onClick={saveSettings} className="mt-6 bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">Save Settings</button>
      </div>
    </div>
  );
};

export default Settings;