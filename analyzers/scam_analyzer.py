import re
from collections import Counter, defaultdict
from datetime import datetime

class ScamAnalyzer:
    def __init__(self):
        self.risk_weights = {'critical': 5, 'high': 3, 'medium': 2, 'low': 1}
        
        self.scam_patterns = {
            'critical': {
                'gambling': [
                    r'\bsatta\s*matka\b', r'\bandar\s*bazar\b', r'\bteen\s*patti\b',
                    r'\blotus\s*365\b', r'\bdragon\s*tiger\b', r'\bonline\s*casino\b',
                ],
                'scam_types': [
                    r'\bponzi\b', r'\bpyramid\b', r'\bmoney\s*laundering\b',
                    r'\bcarding\b', r'\bcloning\b',
                ],
                'hacking': [
                    r'\bcrack\s*(?:software|tool|app)\b', r'\bmod\s*apk\b',
                    r'\bhacked\s*account\b', r'\bpaytm\s*hack\b',
                ]
            },
            'high': {
                'money_promises': [
                    r'\bdouble\s*(?:your\s*)?money\b', r'\bguaranteed\s*profit\b',
                    r'\b100%.{0,20}(?:win|profit|return)\b',
                    r'\bno\s*(?:risk|investment|loss)\b',
                    r'\binstant\s*(?:withdrawal|withdraw|earning)\b',
                    r'\bpassive\s*income\b',
                ],
                'urgency': [
                    r'\blimited\s*(?:time|offer|spots?|seats?)\b',
                    r'\bonly\s*\d+\s*(?:left|remaining|spots?)\b',
                    r'\blast\s*chance\b', r'\bact\s*(?:now|fast)\b',
                ]
            },
            'medium': {
                'financial': [
                    r'\bupi\s*[iI][dD]\b',
                    r'\bbank\s*(?:account|transfer|details)\b',
                    r'\bcvv\b', r'\botp\b',
                ],
                'phone_numbers': [r'\b[6-9]\d{9}\b'],
                'upi_ids': [r'\b[\w.-]+@(?:paytm|phonepe|ybl|axl|apl|upi|icici|sbi|hdfc)\b'],
            },
            'low': {
                'engagement': [
                    r'\blike\s*and\s*share\b', r'\btag\s*your\s*friends\b',
                    r'\bfollow\s*for\s*more\b',
                ],
                'fake_endorsements': [
                    r'\bsecret\s*method\b', r'\brevealed\b',
                    r'\byou\s*won.{0,20}lottery\b'
                ]
            }
        }
    
    def analyze_text(self, text):
        if not text:
            return self._empty_result()
        
        text_lower = text.lower()
        flags = []
        total_weight = 0
        categories_found = set()
        
        for risk_level, categories in self.scam_patterns.items():
            base_weight = self.risk_weights.get(risk_level, 1)
            for category, patterns in categories.items():
                for pattern in patterns:
                    matches = re.findall(pattern, text_lower)
                    if matches:
                        weight = base_weight * len(matches)
                        total_weight += weight
                        categories_found.add(category)
                        flags.append({
                            'risk_level': risk_level,
                            'category': category,
                            'pattern': pattern,
                            'matches': matches[:3],
                            'weight': weight
                        })
        
        risk_score = min(total_weight / 15, 1.0)
        
        if risk_score > 0.6:
            risk_level = 'CRITICAL'
        elif risk_score > 0.4:
            risk_level = 'HIGH'
        elif risk_score > 0.2:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': round(risk_score, 3),
            'risk_level': risk_level,
            'flags': flags,
            'categories': list(categories_found),
            'total_indicators': len(flags),
            'total_weight': total_weight
        }
    
    def extract_entities(self, text):

        entities = {
        'phone_numbers': re.findall(
            r'\b(?:\+91[- ]?)?[6-9]\d{9}\b',
            text
        ),

        'upi_ids': re.findall(
            r'\b[\w.-]+@(?:paytm|phonepe|ybl|axl|apl|upi|icici|sbi|hdfc)\b',
            text,
            re.I
        ),

        'emails': re.findall(
            r'\b[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}\b',
            text
        ),

        'urls': re.findall(
            r'https?://[^\s<>"\']+',
            text
        ),

        'telegram_usernames': re.findall(
            r'(?<!\w)@[A-Za-z0-9_]{5,32}',
            text
        ),

        'telegram_links': re.findall(
            r'(?:https?://)?t\.me/[A-Za-z0-9_+/]+',
            text,
            re.I
        ),

        'domains': re.findall(
            r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|in|net|org|xyz|info|live|bet|casino)\b',
            text,
            re.I
        ),

        'btc_wallets': re.findall(
            r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b',
            text
        ),

        'eth_wallets': re.findall(
            r'\b0x[a-fA-F0-9]{40}\b',
            text
        ),

        'trx_wallets': re.findall(
            r'\bT[A-Za-z1-9]{33}\b',
            text
        ),

        'amounts': re.findall(
            r'(?:rs\.?\s*|₹|inr\s*)(\d+)',
            text,
            re.I
        ),
        }

        return {
        k: list(set(v))
        for k, v in entities.items()
        if v
        }
    
    def _empty_result(self):
        return {
            'risk_score': 0, 'risk_level': 'LOW',
            'flags': [], 'categories': [],
            'total_indicators': 0, 'total_weight': 0
        }
    
    def analyze_content_batch(self, contents):
        results = []
        for content in contents:
            text_parts = [
                content.get('title', ''),
                content.get('description', ''),
                content.get('caption', ''),
                content.get('text', ''),
                ' '.join(content.get('tags', [])),
                ' '.join(content.get('hashtags', []))
            ]
            full_text = ' '.join(filter(None, text_parts))
            
            analysis = self.analyze_text(full_text)
            entities = self.extract_entities(full_text)
            
            content['risk_analysis'] = analysis
            content['entities'] = entities
            results.append(content)
        
        return results
