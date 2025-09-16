import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import NetworkGraph from './components/NetworkGraph';
import PacketInspectorTest from './components/PacketInspectorTest';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <Routes>
            <Route 
              path="/" 
              element={
                <ProtectedRoute>
                  <NetworkGraph />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <NetworkGraph />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/test" 
              element={
                <PacketInspectorTest />
              } 
            />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
