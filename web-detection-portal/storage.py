import json
import os
from typing import List, Dict
from datetime import datetime


class DetectionStorage:
    """Storage manager for detection results using JSON"""
    
    def __init__(self, storage_file: str = 'detection_results.json'):
        """Initialize storage with JSON file"""
        self.storage_file = storage_file
        self._ensure_storage_exists()
    
    def _ensure_storage_exists(self):
        """Create storage file if it doesn't exist"""
        if not os.path.exists(self.storage_file):
            with open(self.storage_file, 'w') as f:
                json.dump([], f)
    
    def save_result(self, result: Dict) -> bool:
        """
        Save a detection result
        
        Args:
            result: Detection result dictionary
        
        Returns:
            True if successful, False otherwise
        """
        try:
            results = self.load_all_results()
            results.append(result)
            
            with open(self.storage_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving result: {e}")
            return False
    
    def load_all_results(self) -> List[Dict]:
        """
        Load all detection results
        
        Returns:
            List of detection result dictionaries
        """
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading results: {e}")
            return []
    
    def get_recent_results(self, limit: int = 50) -> List[Dict]:
        """
        Get most recent detection results
        
        Args:
            limit: Maximum number of results to return
        
        Returns:
            List of recent detection results
        """
        results = self.load_all_results()
        return sorted(results, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
    
    def get_statistics(self) -> Dict:
        """
        Get statistics about stored results
        
        Returns:
            Dictionary with statistics
        """
        results = self.load_all_results()
        total = len(results)
        
        if total == 0:
            return {
                'total': 0,
                'injection_count': 0,
                'normal_count': 0,
                'warning_count': 0,
                'injection_rate': 0.0
            }
        
        injection_count = sum(1 for r in results if r.get('result') == 'Injection')
        warning_count = sum(1 for r in results if r.get('result') == 'Warning')
        normal_count = sum(1 for r in results if r.get('result') == 'Normal')
        
        return {
            'total': total,
            'injection_count': injection_count,
            'normal_count': normal_count,
            'warning_count': warning_count,
            'injection_rate': round((injection_count / total) * 100, 2)
        }
    
    def clear_all_results(self) -> bool:
        """
        Clear all stored results
        
        Returns:
            True if successful
        """
        try:
            with open(self.storage_file, 'w') as f:
                json.dump([], f)
            return True
        except Exception as e:
            print(f"Error clearing results: {e}")
            return False
    
    # Future database migration helpers
    def export_for_database(self) -> List[Dict]:
        """
        Export results in a database-ready format
        This can be customized based on your database schema
        
        Returns:
            List of dictionaries ready for database insertion
        """
        results = self.load_all_results()
        db_ready = []
        
        for result in results:
            db_entry = {
                'tool_name': result.get('tool_name'),
                'description': result.get('description'),
                'result': result.get('result'),
                'severity': result.get('severity'),
                'risk_score': result.get('risk_score'),
                'detected_patterns': json.dumps(result.get('detected_patterns', [])),
                'timestamp': result.get('timestamp')
            }
            db_ready.append(db_entry)
        
        return db_ready
