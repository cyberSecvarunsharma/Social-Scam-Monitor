
#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import pytesseract
from datetime import datetime
from collections import Counter

from collectors.youtube_collector import YouTubeCollector
from collectors.instagram_collector import InstagramCollector
from collectors.twitter_collector import TwitterCollector
from collectors.telegram_collector import TelegramCollector
from analyzers.scam_analyzer import ScamAnalyzer
from analyzers.linker import CrossPlatformLinker
from analyzers.database import ScamDatabase
from analyzers.video_analyzer import VideoFrameAnalyzer

CONFIG = {
    'youtube_keywords': [
        "satta matka", "andar bazar", "teen patti real money",
        "online casino India", "lotus 365", "dragon tiger real cash",
        "double your money scam", "guaranteed investment return",
        "online earning scam", "investment fraud India",
        "paytm hack", "mod apk unlimited money",
        "carding tutorial", "atm card cloning",
    ],
    'instagram_hashtags': [
        'satta', 'matka', 'gambling', 'casino',
        'makemoneyonline', 'earnmoneyonline',
        'investmenttips', 'cryptoinvestment',
        'scamalert', 'fraudalert', 'paytmhack',
    ],
    'twitter_queries': [
        "satta matka result -filter:retweets",
        "online casino India lang:en",
        "real money earning app -filter:retweets",
        "guaranteed profit investment",
    ],
    'telegram_channels': [
    'durov'
    ],
    'max_per_keyword': 30,
}

class SocialScamMonitor:
    def __init__(self):
        self.analyzer = ScamAnalyzer()
        self.linker = CrossPlatformLinker()
        self.db = ScamDatabase()
        self.video_analyzer = VideoFrameAnalyzer()
        self.all_content = []
        self.all_flagged = []
        self.yt_collector = YouTubeCollector()
        self.ig_collector = InstagramCollector()
        self.tw_collector = TwitterCollector()
        self.tg_collector = TelegramCollector()

    def collect_all(self):
        print("\n" + "=" * 60)
        print("PHASE 1: DATA COLLECTION")
        print("=" * 60)
        print("\n[1/3] Collecting YouTube...")
        yt_videos = self.yt_collector.search_by_keywords(CONFIG['youtube_keywords'], CONFIG['max_per_keyword'])
        self.all_content.extend(yt_videos)
        print("\n[2/3] Collecting Instagram...")
        ig_posts = self.ig_collector.search_hashtags(CONFIG['instagram_hashtags'], CONFIG['max_per_keyword'])
        self.all_content.extend(ig_posts)
        print("\n[3/3] Collecting Twitter...")
        tw_tweets = self.tw_collector.search_tweets(CONFIG['twitter_queries'], CONFIG['max_per_keyword'])
        self.all_content.extend(tw_tweets)
        print("\n[4/4] Collecting Telegram...")
        tg_messages = self.tg_collector.collect_channels(CONFIG['telegram_channels'],limit=50)
        self.all_content.extend(tg_messages)
        print(f"\n[+] Total: {len(self.all_content)} items collected")
        return self.all_content

    def analyze_all(self):
        print("\n" + "=" * 60)
        print("PHASE 2: ANALYSIS")
        print("=" * 60)
        print(f"\n[*] Analyzing {len(self.all_content)} items...")
        analyzed = self.analyzer.analyze_content_batch(self.all_content)
        self.all_flagged = [c for c in analyzed if c.get('risk_analysis', {}).get('risk_level') in ['MEDIUM', 'HIGH', 'CRITICAL']]
        risk_counts = Counter(c['risk_analysis']['risk_level'] for c in analyzed)
        print(f"\n  Total: {len(analyzed)}")
        print(f"  Flagged: {len(self.all_flagged)}")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if risk_counts.get(level):
                print(f"    {level}: {risk_counts[level]}")
        print("\n[*] Cross-platform analysis...")
        linked = self.linker.find_connections(self.all_flagged)
        print("\n[*] Saving to database...")
        self.db.save_content(analyzed)
        self.db.save_scan_history(len(analyzed), self.all_flagged)
        stats = self.db.get_statistics()
        print(f"  Total in DB: {stats['total_content']}")
        print(f"  Unique Phones: {stats.get('unique_phones', 0)}")
        print(f"  Unique UPI IDs: {stats.get('unique_upi', 0)}")

        # Video analysis for high-risk content
        print("\n[*] Analyzing videos (OCR)...")
        high_risk_videos = [
            c for c in self.all_flagged
            if c.get('risk_analysis', {}).get('risk_level') in ['HIGH', 'CRITICAL']
            and c.get('source') == 'youtube'
            and c.get('url')
        ]
        
        high_risk_videos = high_risk_videos[:1]

        if high_risk_videos:
            print(f"  Found {len(high_risk_videos)} high-risk videos to analyze")
            video_results = self.video_analyzer.analyze_batch(high_risk_videos, max_videos=3)
            for v in video_results:
                if v.get('video_analysis', {}).get('success'):
                    va = v['video_analysis']
                    if va['scam_percentage'] > 30:
                        v['risk_analysis']['video_verified'] = True
                        v['risk_analysis']['video_scam_percentage'] = va['scam_percentage']
                        v['risk_analysis']['video_findings'] = va['unique_findings']
                        print(f"  ✓ {v.get('title', '')[:60]}: {va['scam_percentage']}% scam frames")
        else:
            print("  No high-risk YouTube videos to analyze")

        return analyzed

    def generate_ai_summary(self, report):
        try:
            prompt = f"""You are a cyber threat intelligence analyst.
Analyze this scam monitoring report and provide:

1. Executive Summary
2. Top Threat Category
3. Most Affected Platform
4. Key Risks
5. Recommendations

Report Data:
Total Collected: {report['summary']['total_collected']}
Total Flagged: {report['summary']['total_flagged']}
Risk Distribution: {report['summary']['by_risk']}
Platforms: {report['summary']['by_platform']}
Top Categories: {report['summary']['top_categories']}
Cross Platform Links: {report['cross_platform']['total_suspicious']}

Keep response under 200 words."""

            result = subprocess.run(
                ["ollama", "run", "llama3.2:3b"],
                input=prompt,
                text=True,
                capture_output=True,
                timeout=60
            )

            return result.stdout.strip()

        except Exception as e:
            return f"AI Summary generation failed: {e}"

    def generate_report(self):
        print("\n" + "=" * 60)
        print("PHASE 3: REPORT")
        print("=" * 60)
        platform_counts = Counter(c.get('source', 'unknown') for c in self.all_flagged)
        all_categories = []
        for c in self.all_flagged:
            all_categories.extend(c.get('risk_analysis', {}).get('categories', []))
        category_counts = Counter(all_categories).most_common(10)
        all_entities = {}
        for c in self.all_flagged:
            for etype, entities in c.get('entities', {}).items():
                if etype not in all_entities:
                    all_entities[etype] = []
                all_entities[etype].extend(entities)
        top_entities = {}
        for etype, entities in all_entities.items():
            top_entities[etype] = Counter(entities).most_common(10)
        report = {
            'scan_info': {'timestamp': datetime.now().isoformat(), 'platforms_used': list(platform_counts.keys())},
            'summary': {
                'total_collected': len(self.all_content),
                'total_flagged': len(self.all_flagged),
                'by_platform': dict(platform_counts),
                'by_risk': dict(Counter(c['risk_analysis']['risk_level'] for c in self.all_flagged)),
                'top_categories': dict(category_counts),
            },
            'cross_platform': {
                'total_suspicious': len(self.linker.suspicious_groups),
                'high_priority': [g for g in self.linker.suspicious_groups if g['max_risk'] in ['CRITICAL', 'HIGH']][:15],
            },
            'top_entities': top_entities,
            'critical_findings': [c for c in self.all_flagged if c.get('risk_analysis', {}).get('risk_level') == 'CRITICAL'],
            'high_risk_findings': [c for c in self.all_flagged if c.get('risk_analysis', {}).get('risk_level') == 'HIGH'],
            'video_verified': [c for c in self.all_flagged if c.get('risk_analysis', {}).get('video_verified')],
            'all_flagged': self.all_flagged,
        }
        print("\n[*] Generating AI Summary...")
        ai_summary = self.generate_ai_summary(report)
        report['ai_summary'] = ai_summary
        os.makedirs('output', exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'output/scam_report_{timestamp}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str, ensure_ascii=False)
        print(f"\n[+] Report saved: {filename}")
        s = report['summary']
        print(f"\n{'=' * 60}")
        print("SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total Scanned: {s['total_collected']}")
        print(f"Total Flagged: {s['total_flagged']}")
        print(f"\nBy Risk:")
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if s['by_risk'].get(level):
                print(f"  {level}: {s['by_risk'][level]}")
        print(f"\nBy Platform:")
        for p, c in s['by_platform'].items():
            print(f"  {p}: {c}")
        print(f"\nCross-Platform Links: {report['cross_platform']['total_suspicious']}")
        print(f"\nVideo Verified: {len(report.get('video_verified', []))}")
        if report['cross_platform']['high_priority']:
            print("\n⚠️  HIGH PRIORITY LINKS:")
            for g in report['cross_platform']['high_priority'][:5]:
                print(f"  {g['entity']} ({g['type']}) - {', '.join(g['platforms'])}")
        
        print("\n" + "=" * 60)
        print("AI THREAT SUMMARY")
        print("=" * 60)
        print(report.get('ai_summary', 'No AI Summary'))
        
        return filename

def main():
    print("\n🔍 SOCIAL SCAM MONITOR v1.0")
    print("Multi-platform scam content detector")
    monitor = SocialScamMonitor()
    try:
        monitor.collect_all()
        monitor.analyze_all()
        report_file = monitor.generate_report()
        print(f"\n✅ Complete! Report: {report_file}")
    except KeyboardInterrupt:
        print("\n\n[!] Stopped by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
