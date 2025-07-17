import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import NetworkGraph from './components/NetworkGraph';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <NetworkGraph />
  </React.StrictMode>
);