import instaloader
from datetime import datetime
import time

class InstagramCollector:
    def __init__(self):
        self.loader = instaloader.Instaloader(
            quiet=True,
            download_videos=False,
            download_pictures=False,
            compress_json=False
        )
        self.logged_in = False
    
    def login(self, username=None, password=None):
        try:
            if username and password:
                self.loader.login(username, password)
                self.logged_in = True
                print("[Instagram] Login successful")
            else:
                print("[Instagram] Skipping login (optional)")
        except Exception as e:
            print(f"[Instagram] Login failed: {e}")
    
    def search_hashtags(self, hashtags, max_per_tag=30):
        all_posts = []
        print(f"[Instagram] Searching {len(hashtags)} hashtags...")
        
        for tag in hashtags:
            try:
                clean_tag = tag.replace('#', '').strip()
                hashtag = instaloader.Hashtag.from_name(
                    self.loader.context, clean_tag
                )
                
                count = 0
                for post in hashtag.get_posts():
                    if count >= max_per_tag:
                        break
                    
                    all_posts.append({
                        'source': 'instagram',
                        'post_id': post.shortcode,
                        'caption': post.caption if post.caption else '',
                        'likes': post.likes,
                        'comments': post.comments,
                        'timestamp': post.date.isoformat(),
                        'owner': post.owner_username,
                        'is_video': post.is_video,
                        'url': f"https://instagram.com/p/{post.shortcode}",
                        'hashtags': post.caption_hashtags if post.caption else [],
                        'matched_hashtag': f"#{clean_tag}",
                        'collected_at': datetime.now().isoformat()
                    })
                    count += 1
                
                print(f"  [+] #{clean_tag}: {count} posts")
                time.sleep(2)
                
            except Exception as e:
                print(f"  [!] #{tag}: {str(e)[:60]}")
        
        print(f"[Instagram] Total: {len(all_posts)}")
        return all_posts
