import os
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional


class Logger:
    """Custom logger for Sayer7 tool"""
    
    def __init__(self, name: str = "Sayer7", log_dir: str = "logs"):
        self.name = name
        self.log_dir = log_dir
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        log_file = os.path.join(self.log_dir, f"{self.name}_{datetime.now().strftime('%Y%m%d')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(self.name)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
    
    def save_results(self, results: Dict[str, Any], filename: str = None, output_format: str = 'json') -> bool:
        """Save scan results to file"""
        try:
            output_dir = "output"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            if not filename:
                filename = f"sayer7_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Ensure filename doesn't include path separators
            filename = os.path.basename(filename)
            
            # Remove extension if already provided
            if filename.endswith(('.json', '.csv', '.txt')):
                filename = filename.rsplit('.', 1)[0]
            
            filepath = os.path.join(output_dir, f"{filename}.{output_format.lower()}")
            
            if output_format.lower() == 'json':
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=4, ensure_ascii=False)
            elif output_format.lower() == 'csv':
                import csv
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    self._flatten_results_for_csv(results, writer)
            elif output_format.lower() == 'txt':
                with open(filepath, 'w', encoding='utf-8') as f:
                    self._format_results_for_txt(results, f)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=4, ensure_ascii=False)
            
            self.logger.info(f"Results saved to: {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
            return False
    
    def _flatten_results_for_csv(self, results: Dict[str, Any], writer):
        """Flatten results for CSV format"""
        writer.writerow(['Type', 'Key', 'Value'])
        for key, value in results.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    writer.writerow([key, sub_key, str(sub_value)])
            elif isinstance(value, list):
                for item in value:
                    writer.writerow([key, 'item', str(item)])
            else:
                writer.writerow([key, key, str(value)])
    
    def _format_results_for_txt(self, results: Dict[str, Any], f):
        """Format results for text format"""
        f.write("Sayer7 Scan Results\n")
        f.write("=" * 50 + "\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        
        for key, value in results.items():
            f.write(f"\n[{key.upper()}]\n")
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    f.write(f"  {sub_key}: {sub_value}\n")
            elif isinstance(value, list):
                for item in value:
                    f.write(f"  - {item}\n")
            else:
                f.write(f"  {value}\n")


class ConfigManager:
    """Configuration manager for Sayer7 tool"""
    
    def __init__(self, config_file: str = "config/config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        default_config = {
            "threads": 10,
            "timeout": 30,
            "user_agent": "Sayer7/1.0",
            "max_depth": 3,
            "max_pages": 100,
            "delay": 1,
            "proxy": {
                "enabled": False,
                "type": "http",
                "host": "127.0.0.1",
                "port": 8080
            },
            "output": {
                "format": "json",
                "directory": "output",
                "filename": "sayer7_results"
            },
            "search_engines": {
                "enabled": True,
                "engines": ["google", "bing", "duckduckgo"],
                "max_results": 100
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                    # Merge with default config
                    default_config.update(loaded_config)
            except Exception as e:
                print(f"Error loading config: {e}")
        
        return default_config
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to JSON file"""
        try:
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value by key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        return self.save_config(self.config)