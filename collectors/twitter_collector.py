import tweepy
from datetime import datetime
import time

class TwitterCollector:
    def __init__(self, bearer_token=None):
        if bearer_token:
            self.client = tweepy.Client(
                bearer_token=bearer_token,
                wait_on_rate_limit=True
            )
            self.has_api = True
        else:
            self.has_api = False
            print("[Twitter] No API token. Will skip Twitter collection.")
    
    def set_bearer_token(self, token):
        self.client = tweepy.Client(
            bearer_token=token,
            wait_on_rate_limit=True
        )
        self.has_api = True
    
    def search_tweets(self, queries, max_per_query=30):
        if not self.has_api:
            print("[Twitter] API token required. Skipping.")
            return []
        
        all_tweets = []
        print(f"[Twitter] Searching {len(queries)} queries...")
        
        for query in queries:
            try:
                response = self.client.search_recent_tweets(
                    query=query,
                    max_results=min(max_per_query, 100),
                    tweet_fields=['created_at', 'public_metrics', 'author_id'],
                    expansions=['author_id']
                )
                
                if response.data:
                    users = {u.id: u.username for u in response.includes.get('users', [])}
                    for tweet in response.data:
                        all_tweets.append({
                            'source': 'twitter',
                            'tweet_id': str(tweet.id),
                            'text': tweet.text,
                            'author': users.get(tweet.author_id, 'unknown'),
                            'created_at': tweet.created_at.isoformat(),
                            'retweets': tweet.public_metrics['retweet_count'],
                            'likes': tweet.public_metrics['like_count'],
                            'replies': tweet.public_metrics['reply_count'],
                            'url': f"https://twitter.com/i/web/status/{tweet.id}",
                            'matched_query': query,
                            'collected_at': datetime.now().isoformat()
                        })
                    print(f"  [+] '{query[:30]}': {len(response.data)} tweets")
                else:
                    print(f"  [-] '{query[:30]}': No results")
                
                time.sleep(1)
            except Exception as e:
                print(f"  [!] '{query[:30]}': {str(e)[:60]}")
        
        print(f"[Twitter] Total: {len(all_tweets)}")
        return all_tweets
