import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Identities from './pages/Identities';
import IdentityDetail from './pages/IdentityDetail';
import Alerts from './pages/Alerts';
import Integrations from './pages/Integrations';
import Compliance from './pages/Compliance';
import Settings from './pages/Settings';
import PrivateRoute from './components/PrivateRoute';
import IdentityGraph from './pages/IdentityGraph';
import Onboarding from './pages/Onboarding';
import SSOComplete from './pages/SSOComplete';

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<PrivateRoute><Layout /></PrivateRoute>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="identities" element={<Identities />} />
            <Route path="identities/:id" element={<IdentityDetail />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="integrations" element={<Integrations />} />
            <Route path="compliance" element={<Compliance />} />
            <Route path="identity-graph" element={<IdentityGraph />} />
            <Route path="settings" element={<Settings />} />
            <Route path="onboarding" element={<Onboarding />} />
          </Route>
          <Route path="/sso-complete" element={<SSOComplete />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
