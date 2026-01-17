"""
Example: Database Integration for MCP Tool Detection System

This file demonstrates how to migrate from JSON storage to a database.
Supports SQLite, PostgreSQL, and MySQL.
"""

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import json

Base = declarative_base()

class DetectionResult(Base):
    """Database model for detection results"""
    __tablename__ = 'detection_results'
    
    id = Column(Integer, primary_key=True)
    tool_name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=False)
    result = Column(String(50), nullable=False, index=True)
    severity = Column(String(50))
    risk_score = Column(Integer)
    detected_patterns = Column(JSON)  # or Text for MySQL
    timestamp = Column(DateTime, default=datetime.now, index=True)
    
    def to_dict(self):
        """Convert to dictionary for API responses"""
        return {
            'id': self.id,
            'tool_name': self.tool_name,
            'description': self.description,
            'result': self.result,
            'severity': self.severity,
            'risk_score': self.risk_score,
            'detected_patterns': self.detected_patterns,
            'timestamp': self.timestamp.isoformat()
        }


class DatabaseStorage:
    """Database storage manager - replaces storage.py"""
    
    def __init__(self, database_url='sqlite:///detection_results.db'):
        """
        Initialize database connection
        
        Examples:
            SQLite: 'sqlite:///detection_results.db'
            PostgreSQL: 'postgresql://user:password@localhost/detection'
            MySQL: 'mysql://user:password@localhost/detection'
        """
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def save_result(self, result: dict) -> bool:
        """Save a detection result to database"""
        try:
            db_result = DetectionResult(
                tool_name=result['tool_name'],
                description=result['description'],
                result=result['result'],
                severity=result['severity'],
                risk_score=result['risk_score'],
                detected_patterns=result['detected_patterns'],
                timestamp=datetime.fromisoformat(result['timestamp'])
            )
            self.session.add(db_result)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error saving result: {e}")
            return False
    
    def load_all_results(self) -> list:
        """Load all detection results"""
        try:
            results = self.session.query(DetectionResult).all()
            return [r.to_dict() for r in results]
        except Exception as e:
            print(f"Error loading results: {e}")
            return []
    
    def get_recent_results(self, limit: int = 50) -> list:
        """Get most recent detection results"""
        try:
            results = self.session.query(DetectionResult)\
                .order_by(DetectionResult.timestamp.desc())\
                .limit(limit)\
                .all()
            return [r.to_dict() for r in results]
        except Exception as e:
            print(f"Error loading recent results: {e}")
            return []
    
    def get_statistics(self) -> dict:
        """Get statistics about stored results"""
        try:
            total = self.session.query(DetectionResult).count()
            
            if total == 0:
                return {
                    'total': 0,
                    'injection_count': 0,
                    'normal_count': 0,
                    'warning_count': 0,
                    'injection_rate': 0.0
                }
            
            injection_count = self.session.query(DetectionResult)\
                .filter(DetectionResult.result == 'Injection').count()
            warning_count = self.session.query(DetectionResult)\
                .filter(DetectionResult.result == 'Warning').count()
            normal_count = self.session.query(DetectionResult)\
                .filter(DetectionResult.result == 'Normal').count()
            
            return {
                'total': total,
                'injection_count': injection_count,
                'normal_count': normal_count,
                'warning_count': warning_count,
                'injection_rate': round((injection_count / total) * 100, 2)
            }
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}
    
    def clear_all_results(self) -> bool:
        """Clear all stored results"""
        try:
            self.session.query(DetectionResult).delete()
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            print(f"Error clearing results: {e}")
            return False
    
    def get_by_tool_name(self, tool_name: str) -> list:
        """Get all results for a specific tool"""
        try:
            results = self.session.query(DetectionResult)\
                .filter(DetectionResult.tool_name == tool_name)\
                .order_by(DetectionResult.timestamp.desc())\
                .all()
            return [r.to_dict() for r in results]
        except Exception as e:
            print(f"Error getting results by tool name: {e}")
            return []
    
    def get_by_severity(self, severity: str) -> list:
        """Get all results with specific severity"""
        try:
            results = self.session.query(DetectionResult)\
                .filter(DetectionResult.severity == severity)\
                .order_by(DetectionResult.timestamp.desc())\
                .all()
            return [r.to_dict() for r in results]
        except Exception as e:
            print(f"Error getting results by severity: {e}")
            return []


# Migration function to convert JSON to database
def migrate_json_to_database(json_file='detection_results.json', 
                             database_url='sqlite:///detection_results.db'):
    """
    Migrate existing JSON data to database
    
    Usage:
        migrate_json_to_database('detection_results.json', 'sqlite:///detection.db')
    """
    print("Starting migration from JSON to database...")
    
    # Load JSON data
    try:
        with open(json_file, 'r') as f:
            json_data = json.load(f)
        print(f"✓ Loaded {len(json_data)} results from JSON")
    except FileNotFoundError:
        print(f"✗ JSON file {json_file} not found")
        return
    
    # Initialize database
    db_storage = DatabaseStorage(database_url)
    print(f"✓ Database initialized at {database_url}")
    
    # Migrate data
    success_count = 0
    for result in json_data:
        if db_storage.save_result(result):
            success_count += 1
    
    print(f"✓ Migration complete: {success_count}/{len(json_data)} results migrated")
    print(f"✓ Database ready at {database_url}")


# Example usage in app.py
"""
To use database storage instead of JSON, replace this line in app.py:

    from storage import DetectionStorage
    storage = DetectionStorage('detection_results.json')

With:

    from db_storage import DatabaseStorage
    storage = DatabaseStorage('sqlite:///detection_results.db')

All other code remains the same!
"""


if __name__ == "__main__":
    # Example: Create database and migrate data
    print("MCP Tool Detection - Database Migration Example")
    print("=" * 60)
    
    # Option 1: SQLite (easiest, no setup required)
    print("\n1. SQLite Example:")
    migrate_json_to_database('detection_results.json', 'sqlite:///detection.db')
    
    # Option 2: PostgreSQL (for production)
    # print("\n2. PostgreSQL Example:")
    # migrate_json_to_database('detection_results.json', 
    #     'postgresql://user:password@localhost:5432/mcp_detection')
    
    # Option 3: MySQL (alternative production option)
    # print("\n3. MySQL Example:")
    # migrate_json_to_database('detection_results.json',
    #     'mysql://user:password@localhost:3306/mcp_detection')
    
    print("\n" + "=" * 60)
    print("Migration complete! Update app.py to use DatabaseStorage")
