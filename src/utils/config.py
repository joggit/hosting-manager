# Create the missing config file
# src/utils/config.py
"""
Configuration management for hosting manager
Handles environment variables, config files, and defaults
"""

import os
import json
from pathlib import Path
import shutil


class Config:
    """Configuration manager with environment and file support"""

    def __init__(self, config_file=None):
        self.config_data = {}
        self._load_defaults()

        if config_file and os.path.exists(config_file):
            self._load_from_file(config_file)

        self._load_from_env()

    def _load_defaults(self):
        """Load default configuration values"""
        self.config_data = {
            # Core paths
            "database_path": "/tmp/hosting/hosting.db",
            "web_root": "/tmp/www/domains",
            "log_dir": "/tmp/hosting/logs",
            # Nginx
            "nginx_sites_dir": "/etc/nginx/sites-available",
            "nginx_enabled_dir": "/etc/nginx/sites-enabled",
            # API settings
            "api_host": "0.0.0.0",
            "api_port": 5000,
            "api_user": "www-data",
            "api_group": "www-data",
            # Monitoring
            "health_check_interval": 60,
            "process_monitor_interval": 30,
            "log_retention_days": 7,
            "monitoring_enabled": True,
            # PM2 settings
            "pm2_home": "/tmp/pm2-home",
            "pm2_log_dir": "/tmp/process-logs",
            # Deployment
            "max_deploy_timeout": 600,
            "npm_cache_dir": "/tmp/npm-cache",
            "deploy_temp_dir": "/tmp/deployments",
            # Security
            "allowed_origins": ["*"],
            "rate_limit_enabled": False,
            # System
            "readonly_mode": False,
            "debug_mode": False,
        }

    def _load_from_file(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, "r") as f:
                file_config = json.load(f)
                self.config_data.update(file_config)
        except Exception as e:
            print(f"Warning: Could not load config file {config_file}: {e}")

    def _load_from_env(self):
        """Load configuration from environment variables"""
        env_mapping = {
            "HOSTING_DB_PATH": "database_path",
            "HOSTING_WEB_ROOT": "web_root",
            "HOSTING_LOG_DIR": "log_dir",
            "HOSTING_API_HOST": "api_host",
            "HOSTING_API_PORT": "api_port",
            "HOSTING_HEALTH_INTERVAL": "health_check_interval",
            "HOSTING_MONITOR_INTERVAL": "process_monitor_interval",
            "HOSTING_DEBUG": "debug_mode",
            "PM2_HOME": "pm2_home",
        }

        for env_var, config_key in env_mapping.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Type conversion
                if config_key.endswith("_port") or config_key.endswith("_interval"):
                    try:
                        self.config_data[config_key] = int(env_value)
                    except ValueError:
                        pass
                elif config_key.endswith("_mode") or config_key.endswith("_enabled"):
                    self.config_data[config_key] = env_value.lower() in (
                        "true",
                        "1",
                        "yes",
                        "on",
                    )
                else:
                    self.config_data[config_key] = env_value

    def get(self, key, default=None):
        """Get configuration value"""
        return self.config_data.get(key, default)

    def set(self, key, value):
        """Set configuration value"""
        self.config_data[key] = value

    def update(self, config_dict):
        """Update multiple configuration values"""
        self.config_data.update(config_dict)

    def save_to_file(self, config_file):
        """Save current configuration to file"""
        try:
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, "w") as f:
                json.dump(self.config_data, f, indent=2)
            return True
        except Exception as e:
            print(f"Failed to save config to {config_file}: {e}")
            return False

    def to_dict(self):
        """Get all configuration as dictionary"""
        return self.config_data.copy()

    def validate(self):
        """Validate configuration values"""
        errors = []

        # Check required paths exist or can be created
        path_keys = ["database_path", "web_root", "log_dir"]
        for key in path_keys:
            path = self.get(key)
            if path:
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create directory for {key}: {path} - {e}")

        # Check port ranges
        port_keys = ["api_port"]
        for key in port_keys:
            port = self.get(key)
            if port and not (1 <= port <= 65535):
                errors.append(f"Invalid port for {key}: {port}")

        # Check intervals
        interval_keys = ["health_check_interval", "process_monitor_interval"]
        for key in interval_keys:
            interval = self.get(key)
            if interval and interval < 10:
                errors.append(
                    f"Interval too short for {key}: {interval}s (minimum 10s)"
                )

        return errors
