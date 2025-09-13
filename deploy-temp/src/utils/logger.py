# src/utils/logger.py
"""
Enhanced logging system for hosting manager
Provides structured logging with file rotation and different log levels
"""

import logging
import logging.handlers
import os
import sys
import json  # For structured logging
from datetime import datetime


class Logger:
    """Enhanced logging system with file rotation"""

    def __init__(self, log_level=logging.INFO, log_dir="/tmp/hosting/logs"):
        self.log_dir = log_dir
        self.log_level = log_level

        # Create log directory
        os.makedirs(log_dir, mode=0o755, exist_ok=True)

        # Setup loggers
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """Setup the main logger with handlers"""
        logger = logging.getLogger("hosting_manager")
        logger.setLevel(self.log_level)

        # Clear existing handlers
        logger.handlers.clear()

        # Create formatters
        detailed_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )

        simple_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(simple_formatter)
        logger.addHandler(console_handler)

        # File handler with rotation
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                filename=os.path.join(self.log_dir, "hosting_manager.log"),
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not setup file logging: {e}")

        # Error file handler
        try:
            error_handler = logging.handlers.RotatingFileHandler(
                filename=os.path.join(self.log_dir, "hosting_manager_error.log"),
                maxBytes=5 * 1024 * 1024,  # 5MB
                backupCount=3,
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(detailed_formatter)
            logger.addHandler(error_handler)
        except Exception as e:
            logger.warning(f"Could not setup error file logging: {e}")

        return logger

    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)

    def info(self, message):
        """Log info message"""
        self.logger.info(message)

    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message):
        """Log error message"""
        self.logger.error(message)

    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)

    def log_deployment(self, domain_name, action, status, message="", details=""):
        """Log deployment action with structured data"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "domain": domain_name,
            "action": action,
            "status": status,
            "message": message,
            "details": details,
        }

        self.info(f"DEPLOYMENT: {json.dumps(log_entry)}")

    def log_process_action(self, process_name, action, status, details=""):
        """Log process management action"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "process": process_name,
            "action": action,
            "status": status,
            "details": details,
        }

        self.info(f"PROCESS: {json.dumps(log_entry)}")

    def log_health_check(self, service_name, status, response_time=None, error=None):
        """Log health check result"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "service": service_name,
            "health_status": status,
            "response_time": response_time,
            "error": error,
        }

        if status == "healthy":
            self.debug(f"HEALTH: {json.dumps(log_entry)}")
        else:
            self.warning(f"HEALTH: {json.dumps(log_entry)}")

    def set_log_level(self, level):
        """Change log level dynamically"""
        if isinstance(level, str):
            level = getattr(logging, level.upper())

        self.logger.setLevel(level)
        self.log_level = level

    def get_recent_logs(self, lines=100):
        """Get recent log entries"""
        try:
            log_file = os.path.join(self.log_dir, "hosting_manager.log")
            if os.path.exists(log_file):
                with open(log_file, "r") as f:
                    log_lines = f.readlines()
                    return log_lines[-lines:] if len(log_lines) > lines else log_lines
        except Exception as e:
            self.error(f"Failed to read log file: {e}")

        return []
