import yt_dlp
import json
import os
from datetime import datetime

class YouTubeCollector:
    def __init__(self):
        self.ydl_opts = {
            'quiet': True,
            'no_warnings': True,
            'extract_flat': True,
            'force_json': True,
        }
    
    def search_by_keywords(self, keywords, max_per_keyword=30):
        all_videos = []
        print(f"[YouTube] Searching {len(keywords)} keywords...")
        
        for keyword in keywords:
            try:
                query = f"ytsearch{max_per_keyword}:{keyword}"
                with yt_dlp.YoutubeDL(self.ydl_opts) as ydl:
                    info = ydl.extract_info(query, download=False)
                    
                    for entry in info.get('entries', []):
                        all_videos.append({
                            'source': 'youtube',
                            'video_id': entry.get('id'),
                            'title': entry.get('title', ''),
                            'description': entry.get('description', ''),
                            'channel': entry.get('channel', ''),
                            'views': entry.get('view_count', 0),
                            'duration': entry.get('duration', 0),
                            'upload_date': entry.get('upload_date', ''),
                            'tags': entry.get('tags', []),
                            'url': f"https://youtube.com/watch?v={entry.get('id')}",
                            'matched_keyword': keyword,
                            'collected_at': datetime.now().isoformat()
                        })
                print(f"  [+] '{keyword[:30]}': {len(info.get('entries', []))} videos")
            except Exception as e:
                print(f"  [!] '{keyword[:30]}': {str(e)[:60]}")
        
        # Duplicates hatao
        seen = set()
        unique = []
        for v in all_videos:
            if v['video_id'] not in seen:
                seen.add(v['video_id'])
                unique.append(v)
        
        print(f"[YouTube] Total unique: {len(unique)}")
        return unique
