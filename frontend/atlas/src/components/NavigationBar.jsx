import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import styles from './NavigationBar.module.css';

const NavigationBar = ({ activeTab, onTabChange, devices, totalConnections, onDeviceSelect, selectedDeviceIp, showGraph, onToggleView, onFilterApplied, filteredDevices, setFilteredDevices }) => {
    const { user, logout } = useAuth();
    const [filterText, setFilterText] = useState('');
    const [activeFilters, setActiveFilters] = useState([]);
    const [isFilterLoading, setIsFilterLoading] = useState(false);
    const [filterError, setFilterError] = useState('');
    const [showUserMenu, setShowUserMenu] = useState(false);
    
    const [settings, setSettings] = useState({
        auto_refresh: true,
        show_connection_details: false,
        enable_animations: true,
        refresh_interval: 10,
        network_interface: null,
        capture_filter: null
    });
    const [isSettingsLoading, setIsSettingsLoading] = useState(false);

    const tabs = [
        { id: 'filters', label: 'Wireshark Filters', icon: '🔍' },
        { id: 'settings', label: 'Settings', icon: '⚙️' },
        { id: 'devices', label: showGraph ? 'Device Tab' : 'Graph Tab', icon: showGraph ? '📱' : '🕸️' }
    ];

    useEffect(() => {
        loadSettings();
        loadActiveFilters();
    }, []);

    const loadSettings = async () => {
        try {
            const response = await axios.get('http://localhost:8000/settings');
            setSettings(response.data);
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    };

    const loadActiveFilters = async () => {
        try {
            const response = await axios.get('http://localhost:8000/filters/active');
            setActiveFilters(response.data.active_filters || []);
        } catch (error) {
            console.error('Failed to load active filters:', error);
        }
    };

    const handleFilterChange = (e) => {
        setFilterText(e.target.value);
        setFilterError('');
    };

    const clearFilter = async () => {
        try {
            setIsFilterLoading(true);
            setFilterError('');
            
            setFilterText('');
            
            await axios.post('http://localhost:8000/filters/clear');
            setActiveFilters([]);
            
            if (setFilteredDevices) {
                setFilteredDevices(null);
            }
            if (onFilterApplied) {
                onFilterApplied(null);
            }
            
        } catch (error) {
            console.error('Failed to clear filters:', error);
            setFilterError('Failed to clear filters');
        } finally {
            setIsFilterLoading(false);
        }
    };

    const applyFilter = async () => {
        if (!filterText.trim()) return;
        
        try {
            setIsFilterLoading(true);
            setFilterError('');
            
            const response = await axios.post('http://localhost:8000/filters/apply', {
                filter_expression: filterText.trim()
            });
            
            const { devices: filtered, total_matches } = response.data;
            
            await loadActiveFilters();
            
            if (setFilteredDevices) {
                setFilteredDevices(filtered);
            }
            if (onFilterApplied) {
                onFilterApplied(filtered);
            }
            
            console.log(`Filter applied: ${filterText}. Found ${total_matches} matching connections.`);
            
        } catch (error) {
            console.error('Failed to apply filter:', error);
            const detail = error.response?.data?.detail;
            let errorMessage = '';
            if (Array.isArray(detail)) {
                errorMessage = detail.map(d => d?.msg || JSON.stringify(d)).join('; ');
            } else if (typeof detail === 'object' && detail !== null) {
                errorMessage = detail.msg || JSON.stringify(detail);
            } else if (typeof detail === 'string') {
                errorMessage = detail;
            } else {
                errorMessage = error.response?.data?.message || error.message || 'Failed to apply filter';
            }
            setFilterError(errorMessage);
        } finally {
            setIsFilterLoading(false);
        }
    };

    const handleSettingChange = async (settingKey, value) => {
        try {
            setIsSettingsLoading(true);
            const updatedSettings = { ...settings, [settingKey]: value };
            
            const response = await axios.put('http://localhost:8000/settings', updatedSettings);
            setSettings(response.data);
            
        } catch (error) {
            console.error('Failed to update setting:', error);
        } finally {
            setIsSettingsLoading(false);
        }
    };

    return (
        <nav className={styles.navigationBar}>
            <div className={styles.navHeader}>
                <img className={styles.logo} src="Atlas_Color.png"></img>
            </div>
            
            <div className={styles.tabContainer}>
                {tabs.map(tab => (
                    <button
                        key={tab.id}
                        className={`${styles.tab} ${activeTab === tab.id ? styles.tabActive : ''}`}
                        onClick={() => onTabChange(tab.id)}
                    >
                        <span className={styles.tabIcon}>{tab.icon}</span>
                        <span className={styles.tabLabel}>{tab.label}</span>
                    </button>
                ))}
                
                <div className={styles.userProfile}>
                    <div className={styles.userAvatar}>
                        {user?.avatar_url ? (
                            <img 
                                src={user.avatar_url} 
                                alt={user.name}
                                className={styles.avatarImage}
                            />
                        ) : (
                            <div className={styles.avatarPlaceholder}>
                                {user?.name?.charAt(0) || '?'}
                            </div>
                        )}
                    </div>
                    <div className={styles.userInfo}>
                        <div className={styles.userName}>{user?.name || 'User'}</div>
                        <div className={styles.userEmail}>{user?.email || 'No email'}</div>
                    </div>
                    <button 
                        className={styles.logoutButton}
                        onClick={() => {
                            if (window.confirm('Are you sure you want to log out?')) {
                                logout();
                            }
                        }}
                        title="Logout"
                    >
                        🚪
                    </button>
                </div>
            </div>

            {activeTab === 'filters' && (
                <div className={styles.filterSection}>
                    <div className={styles.filterInputGroup}>
                        <input
                            type="text"
                            className={styles.filterInput}
                            placeholder="Enter Wireshark filter (e.g., tcp.port == 80)"
                            value={filterText}
                            onChange={handleFilterChange}
                        />
                        <button 
                            className={styles.filterButton}
                            onClick={applyFilter}
                            disabled={!filterText.trim() || isFilterLoading}
                        >
                            {isFilterLoading ? 'Applying...' : 'Apply'}
                        </button>
                        <button 
                            className={styles.clearButton}
                            onClick={clearFilter}
                            disabled={isFilterLoading || (!filterText.trim() && activeFilters.length === 0)}
                        >
                            {isFilterLoading ? 'Clearing...' : 'Clear'}
                        </button>
                    </div>
                    <div className={styles.filterHints}>
                        <span className={styles.hintLabel}>Common filters:</span>
                        <div className={styles.filterChips}>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('http')}
                            >
                                HTTP Traffic
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('https')}
                            >
                                HTTPS Traffic
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('dns')}
                            >
                                DNS Traffic
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('ssh')}
                            >
                                SSH
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('ftp')}
                            >
                                FTP
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('icmp')}
                            >
                                ICMP
                            </button>
                        </div>
                        <div className={styles.filterChips}>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('tcp')}
                            >
                                TCP Protocol
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('udp')}
                            >
                                UDP Protocol
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('host 192.168.1.1')}
                            >
                                Specific Host
                            </button>
                            <button 
                                className={styles.filterChip}
                                onClick={() => setFilterText('net 192.168.0.0/24')}
                            >
                                Local Network
                            </button>
                        </div>
                    </div>
                    
                    {filterError && (
                        <div className={styles.filterError}>
                            {filterError}
                        </div>
                    )}
                </div>
            )}

            {activeTab === 'settings' && (
                <div className={styles.settingsSection}>
                    <div className={styles.settingGroup}>
                        <label className={styles.settingLabel}>
                            <input 
                                type="checkbox" 
                                className={styles.checkbox} 
                                checked={settings.auto_refresh}
                                onChange={(e) => handleSettingChange('auto_refresh', e.target.checked)}
                                disabled={isSettingsLoading}
                            />
                            Auto-refresh data
                        </label>
                        <label className={styles.settingLabel}>
                            <input 
                                type="checkbox" 
                                className={styles.checkbox}
                                checked={settings.show_connection_details}
                                onChange={(e) => handleSettingChange('show_connection_details', e.target.checked)}
                                disabled={isSettingsLoading}
                            />
                            Show connection details
                        </label>
                        <label className={styles.settingLabel}>
                            <input 
                                type="checkbox" 
                                className={styles.checkbox}
                                checked={settings.enable_animations}
                                onChange={(e) => handleSettingChange('enable_animations', e.target.checked)}
                                disabled={isSettingsLoading}
                            />
                            Enable animations
                        </label>
                    </div>
                    <div className={styles.settingGroup}>
                        <label className={styles.settingLabel}>
                            Refresh interval (seconds):
                            <select 
                                className={styles.select}
                                value={settings.refresh_interval}
                                onChange={(e) => handleSettingChange('refresh_interval', parseInt(e.target.value))}
                                disabled={isSettingsLoading}
                            >
                                <option value={5}>5</option>
                                <option value={10}>10</option>
                                <option value={30}>30</option>
                                <option value={60}>60</option>
                            </select>
                        </label>
                    </div>
                    
                    {activeFilters.length > 0 && (
                        <div className={styles.settingGroup}>
                            <div className={styles.settingLabel}>Active Filters:</div>
                            <div className={styles.activeFilters}>
                                {activeFilters.map((filter, index) => (
                                    <div key={index} className={styles.activeFilter}>
                                        <span className={styles.filterText}>{filter}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    
                    {isSettingsLoading && (
                        <div className={styles.loadingIndicator}>
                            Updating settings...
                        </div>
                    )}
                </div>
            )}


        </nav>
    );
};

export default NavigationBar;
