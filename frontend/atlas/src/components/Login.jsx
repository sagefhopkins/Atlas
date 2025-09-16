import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import styles from './Login.module.css';

const Login = () => {
  const { loginWithGoogle, authConfig, loading } = useAuth();
  const [error, setError] = useState('');
  const [isGoogleLoaded, setIsGoogleLoaded] = useState(false);

  useEffect(() => {
    if (authConfig?.google_client_id && !window.google) {
      const script = document.createElement('script');
      script.src = 'https://accounts.google.com/gsi/client';
      script.async = true;
      script.defer = true;
      script.onload = () => {
        setIsGoogleLoaded(true);
        initializeGoogle();
      };
      document.head.appendChild(script);

      return () => {
        document.head.removeChild(script);
      };
    } else if (window.google && authConfig?.google_client_id) {
      setIsGoogleLoaded(true);
      initializeGoogle();
    }
  }, [authConfig]);

  const initializeGoogle = () => {
    if (!window.google || !authConfig?.google_client_id) return;

    window.google.accounts.id.initialize({
      client_id: authConfig.google_client_id,
      callback: handleGoogleResponse,
      auto_select: false,
    });

    window.google.accounts.id.renderButton(
      document.getElementById('google-signin-button'),
      {
        theme: 'outline',
        size: 'large',
        type: 'standard',
        text: 'signin_with',
        shape: 'rectangular',
      }
    );
  };

  const handleGoogleResponse = async (response) => {
    setError('');
    
    try {
      const result = await loginWithGoogle({
        credential: response.credential,
        id_token: response.credential
      });

      if (!result.success) {
        setError(result.error || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('An unexpected error occurred');
    }
  };

  if (loading) {
    return (
      <div className={styles.container}>
        <div className={styles.loadingSpinner}>
          <div className={styles.spinner}></div>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.container}>
      <div className={styles.loginCard}>
        <div className={styles.header}>
          <h1 className={styles.title}>Atlas Network Monitor</h1>
          <p className={styles.subtitle}>Please sign in to continue</p>
        </div>

        <div className={styles.content}>
          {error && (
            <div className={styles.errorMessage}>
              <span className={styles.errorIcon}>⚠️</span>
              {error}
            </div>
          )}

          <div className={styles.loginOptions}>
            {isGoogleLoaded && authConfig?.google_client_id ? (
              <div className={styles.googleSigninContainer}>
                <div id="google-signin-button" className={styles.googleButton}></div>
              </div>
            ) : (
              <div className={styles.loadingButton}>
                <div className={styles.buttonSpinner}></div>
                <span>Loading Google Sign-In...</span>
              </div>
            )}
          </div>
        </div>

        <div className={styles.footer}>
          <p>Secure login powered by Google OAuth 2.0</p>
        </div>
      </div>
    </div>
  );
};

export default Login;
