from collections import defaultdict
import json
from datetime import datetime

class CrossPlatformLinker:
    def __init__(self):
        self.entity_map = defaultdict(list)
        self.suspicious_groups = []
    
    def find_connections(self, all_contents):
        print("[Linker] Finding cross-platform connections...")
        
        for content in all_contents:
            entities = content.get('entities', {})
            platform = content.get('source', 'unknown')
            
            for entity_type, entity_list in entities.items():
                for entity in entity_list:
                    self.entity_map[entity].append({
                        'platform': platform,
                        'url': content.get('url', ''),
                        'risk_level': content.get('risk_analysis', {}).get('risk_level', 'LOW')
                    })
        
        for entity, occurrences in self.entity_map.items():
            platforms_used = set(o['platform'] for o in occurrences)
            
            if len(platforms_used) >= 2 or len(occurrences) >= 3:
                if entity.startswith(('0x', 'bc1', '1', '3')) and len(entity) >= 25:
                    etype = 'crypto_wallet'
                elif 't.me/' in entity.lower():
                    etype = 'telegram_link'
                elif entity.startswith('@'):
                    etype = 'telegram_user'
                elif '@' in entity and any(
                    x in entity.lower()
                    for x in ['paytm','phonepe','ybl','icic','sbi','hdfc']
                    ):
                    etype = 'upi_id'
                elif '@' in entity:
                    etype = 'email'
                elif entity.replace('+91','').replace('','').isdigit():
                    etype = 'phone'
                elif '.' in entity:
                    etype = 'domain'
                else:
                    etype = 'other'
                
                self.suspicious_groups.append({
                    'entity': entity,
                    'type': etype,
                    'platforms': list(platforms_used),
                    'occurrences': len(occurrences),
                    'max_risk': max(o['risk_level'] for o in occurrences)
                })
        
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.suspicious_groups.sort(key=lambda x: risk_order.get(x['max_risk'], 99))
        
        print(f"[Linker] Found {len(self.suspicious_groups)} cross-platform entities")
        return self.suspicious_groups
