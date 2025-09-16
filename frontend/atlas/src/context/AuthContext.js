import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';
import {jwtDecode} from 'jwt-decode';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authConfig, setAuthConfig] = useState(null);

  // Get API base URL
  const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  useEffect(() => {
    // Initialize authentication
    initAuth();
  }, []);

  const initAuth = async () => {
    try {
      // Get auth configuration
      const configResponse = await axios.get(`${API_BASE_URL}/auth/config`);
      setAuthConfig(configResponse.data);
      
      // Check if user is already logged in
      const token = localStorage.getItem('atlas_token');
      if (token) {
        try {
          // Verify token is not expired
          const decoded = jwtDecode(token);
          if (decoded.exp * 1000 > Date.now()) {
            // Token is valid, get user info
            axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
            const userResponse = await axios.get(`${API_BASE_URL}/auth/me`);
            setUser(userResponse.data);
          } else {
            // Token expired, remove it
            localStorage.removeItem('atlas_token');
          }
        } catch (error) {
          console.error('Token validation error:', error);
          localStorage.removeItem('atlas_token');
        }
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
    } finally {
      setLoading(false);
    }
  };

  const loginWithGoogle = async (googleResponse) => {
    try {
      setLoading(true);
      
      console.log('Google response received:', googleResponse);
      
      // Handle different response formats from Google Sign-In
      let tokenData = {};
      
      if (googleResponse.credential) {
        // New Google Identity Services format
        tokenData = {
          credential: googleResponse.credential,
          id_token: googleResponse.credential
        };
      } else if (googleResponse.id_token) {
        // Legacy format
        tokenData = {
          id_token: googleResponse.id_token,
          access_token: googleResponse.access_token
        };
      } else {
        throw new Error('No valid token found in Google response');
      }
      
      console.log('Sending token data to backend:', tokenData);
      
      // Send Google tokens to backend
      const response = await axios.post(`${API_BASE_URL}/auth/google`, tokenData);

      const { access_token, user: userData } = response.data;

      // Store token
      localStorage.setItem('atlas_token', access_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;

      setUser(userData);
      return { success: true };
    } catch (error) {
      console.error('Google login error:', error);
      console.error('Error details:', error.response?.data);
      return { 
        success: false, 
        error: error.response?.data?.detail || error.message || 'Login failed' 
      };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      // Call backend logout endpoint
      if (user) {
        await axios.post(`${API_BASE_URL}/auth/logout`);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear local storage and state regardless of backend response
      localStorage.removeItem('atlas_token');
      delete axios.defaults.headers.common['Authorization'];
      setUser(null);
    }
  };

  const isAuthenticated = () => {
    return user !== null;
  };

  const getToken = () => {
    return localStorage.getItem('atlas_token');
  };

  const value = {
    user,
    loading,
    authConfig,
    loginWithGoogle,
    logout,
    isAuthenticated,
    getToken,
    API_BASE_URL
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
