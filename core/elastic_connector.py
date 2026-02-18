from elasticsearch import Elasticsearch
from config.settings import ELASTIC_HOST, ELASTIC_USER, ELASTIC_PASSWORD, ELASTIC_INDEX_PATTERN
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class ElasticConnector:
    def __init__(self):
        self.host = ELASTIC_HOST
        self.index_pattern = ELASTIC_INDEX_PATTERN
        
        # Setup connection
        if ELASTIC_USER and ELASTIC_PASSWORD:
            self.es = Elasticsearch(
                [self.host],
                basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
                verify_certs=False
            )
        else:
            self.es = Elasticsearch([self.host], verify_certs=False)
    
    def test_connection(self):
        """Test connection to Elasticsearch"""
        try:
            return self.es.ping()
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            return False
    
    def get_recent_logs(self, minutes=60, size=100):
        """Get recent logs from Elasticsearch"""
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{minutes}m",
                            "lt": "now"
                        }
                    }
                },
                "sort": [{"@timestamp": "desc"}],
                "size": size
            }
            
            result = self.es.search(index=self.index_pattern, body=query)
            return [hit['_source'] for hit in result['hits']['hits']]
            
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return []
    
    def count_failed_logins(self, minutes=5):
        """Count failed login attempts in last X minutes"""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}},
                            {"term": {"event_type": "failed_login"}}
                        ]
                    }
                }
            }
            
            result = self.es.count(index=self.index_pattern, body=query)
            return result['count']
            
        except Exception as e:
            logger.error(f"Error counting failed logins: {e}")
            return 0
    
    def get_top_attackers(self, minutes=60, size=10):
        """Get top attacking IPs"""
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{minutes}m"
                        }
                    }
                },
                "aggs": {
                    "top_ips": {
                        "terms": {
                            "field": "src_ip.keyword",
                            "size": size
                        }
                    }
                },
                "size": 0
            }
            
            result = self.es.search(index=self.index_pattern, body=query)
            buckets = result['aggregations']['top_ips']['buckets']
            
            return [{"ip": bucket['key'], "count": bucket['doc_count']} 
                   for bucket in buckets]
                   
        except Exception as e:
            logger.error(f"Error getting top attackers: {e}")
            return []
    
    def get_attack_timeline(self, minutes=60):
        """Get timeline of attacks"""
        try:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{minutes}m"
                        }
                    }
                },
                "aggs": {
                    "attacks_over_time": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "5m"
                        }
                    }
                },
                "size": 0
            }
            
            result = self.es.search(index=self.index_pattern, body=query)
            return result['aggregations']['attacks_over_time']['buckets']
            
        except Exception as e:
            logger.error(f"Error getting attack timeline: {e}")
            return []
