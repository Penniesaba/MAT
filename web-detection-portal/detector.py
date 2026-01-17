import yaml
import re
from datetime import datetime
from typing import Dict, List, Tuple


class MCPToolDetector:
    """Engine for detecting malicious patterns in MCP tool descriptions"""
    
    def __init__(self, rules_file: str = 'detection_rules.yaml'):
        """Initialize detector with rules from YAML file"""
        with open(rules_file, 'r') as f:
            self.rules = yaml.safe_load(f)
        
        self.suspicious_keywords = self.rules['suspicious_keywords']
        self.risk_scoring = self.rules['risk_scoring']
        self.threshold = self.rules['threshold']
    
    def detect(self, tool_name: str, description: str) -> Dict:
        """
        Detect if a tool description contains malicious patterns
        
        Args:
            tool_name: Name of the MCP tool
            description: Tool description to analyze
        
        Returns:
            Dictionary with detection results
        """
        # Convert description to lowercase for case-insensitive matching
        description_lower = description.lower()
        
        # Track matches by category
        matches = {
            'file_access': [],
            'network': [],
            'execution': []
        }
        
        # Check each category
        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                # Use word boundary matching for more accurate detection
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                if re.search(pattern, description_lower):
                    matches[category].append(keyword)
        
        # Calculate risk score
        risk_score = 0
        detected_patterns = []
        
        for category, matched_keywords in matches.items():
            if matched_keywords:
                category_score = len(matched_keywords) * self.risk_scoring[category]
                risk_score += category_score
                detected_patterns.append({
                    'category': category,
                    'keywords': matched_keywords,
                    'score': category_score
                })
        
        # Determine result based on threshold
        if risk_score >= self.threshold['block']:
            result = 'Injection'
            severity = 'critical'
        elif risk_score >= self.threshold['warn']:
            result = 'Warning'
            severity = 'medium'
        else:
            result = 'Normal'
            severity = 'low'
        
        # Return detection report
        return {
            'tool_name': tool_name,
            'description': description,
            'result': result,
            'severity': severity,
            'risk_score': risk_score,
            'detected_patterns': detected_patterns,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_stats(self) -> Dict:
        """Get statistics about detection rules"""
        return {
            'total_keywords': sum(len(keywords) for keywords in self.suspicious_keywords.values()),
            'categories': list(self.suspicious_keywords.keys()),
            'thresholds': self.threshold
        }
