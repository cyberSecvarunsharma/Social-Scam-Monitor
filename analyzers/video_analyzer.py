import cv2
import numpy as np
import pytesseract
from PIL import Image
import requests
from io import BytesIO
import re
import os
import tempfile
import yt_dlp
from datetime import datetime

class VideoFrameAnalyzer:
    """
    Videos aur images se text extract karo aur scam patterns check karo.
    OCR + Object Detection dono use karta hai.
    """
    
    def __init__(self):
        # Scam patterns jo video frames mein dikh sakte hain
        self.scam_overlay_patterns = [
            # Gambling
            (r'\bsatta\s*(?:matka|result|king|live)\b', 'gambling'),
            (r'\bandar\s*bazar\b', 'gambling'),
            (r'\bteen\s*patti\b', 'gambling'),
            (r'\blotus\s*365\b', 'gambling'),
            (r'\bonline\s*casino\b', 'gambling'),
            (r'\blive\s*casino\b', 'gambling'),
            (r'\bjackpot\b', 'gambling'),
            (r'\broulette\b', 'gambling'),
            # Money promises
            (r'\bdouble\s*(?:your\s*)?money\b', 'money_scam'),
            (r'\bguaranteed\s*(?:profit|win|return)\b', 'money_scam'),
            (r'\b100%.{0,15}(?:safe|win|profit|return|guaranteed)\b', 'money_scam'),
            (r'\bno\s*(?:risk|loss|investment)\b', 'money_scam'),
            (r'\binstant\s*(?:withdrawal|withdraw|earning|profit)\b', 'money_scam'),
            (r'\bpassive\s*income\b', 'money_scam'),
            # Urgency
            (r'\blimited\s*(?:time|offer|spots?|seats?)\b', 'urgency'),
            (r'\bonly\s*\d+\s*(?:left|remaining|spots?)\b', 'urgency'),
            (r'\bact\s*(?:now|fast|quickly)\b', 'urgency'),
            # Contact
            (r'\b[6-9]\d{9}\b', 'phone'),
            (r'\b\w+@(?:paytm|phonepe|ybl|axl|apl|upi)\b', 'upi'),
            # Scam phrases
            (r'\b(?:earning|money|profit|income)\s*(?:app|website|platform)\b', 'scam_app'),
            (r'\bmin\s*(?:deposit|investment|bet)\s*(?:₹|rs)\s*\d+\b', 'min_deposit'),
            (r'\brefer\s*(?:and|&)\s*earn\b', 'referral_scam'),
        ]
        
        # Gambling-related objects ke labels (for YOLO)
        self.gambling_objects = [
            'playing cards', 'card', 'dice', 'chips', 'poker',
            'roulette wheel', 'slot machine', 'lottery ticket',
            'cash', 'money', 'betting slip', 'casino table'
        ]
        
        print("[VideoAnalyzer] Initialized with OCR + pattern detection")
    
    def analyze_image(self, image_source):
        """
        Single image analyze karo.
        image_source: URL ya local file path ho sakta hai.
        """
        try:
            # Image load karo
            if str(image_source).startswith('http'):
                response = requests.get(image_source, timeout=10)
                img = Image.open(BytesIO(response.content))
            else:
                img = Image.open(image_source)
            
            # OCR - text extract karo
            text = pytesseract.image_to_string(img, lang='eng+hin')
            
            # Scam patterns check karo
            findings = self._check_patterns(text)
            
            # Convert to OpenCV format for further analysis
            cv_img = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            
            return {
                'success': True,
                'extracted_text': text.strip(),
                'text_length': len(text.strip()),
                'findings': findings,
                'scam_detected': len(findings) > 0
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'extracted_text': '',
                'findings': [],
                'scam_detected': False
            }
    
    def analyze_video_url(self, youtube_url, sample_interval=15):
        """
        YouTube video ke frames analyze karo.
        sample_interval: har kitne seconds par frame analyze karna hai.
        """
        print(f"[VideoAnalyzer] Downloading video: {youtube_url[:50]}...")
        
        try:
            # Video download karo (temp file)
            temp_dir = tempfile.mkdtemp()
            
            ydl_opts = {
                'format': 'mp4',  # Small size for speed
                'outtmpl': os.path.join(temp_dir, '%(id)s.%(ext)s'),
                'quiet': True,
                'no_warnings': True,
            }
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(youtube_url, download=True)
                duration = info.get('duration', 0)
                title = info.get('title', 'Unknown')
                temp_path = ydl.prepare_filename(info)

            print(f"[VideoAnalyzer] Analyzing frames... (duration: {duration}s)")

            # Frames analyze karo
            results = self._analyze_video_frames(temp_path, sample_interval, duration)
            
            # Temp file delete karo
            os.unlink(temp_path)
            
            # Summary
            scam_frames = [r for r in results if r['scam_detected']]
            
            # Combined findings
            all_findings = []
            for r in results:
                all_findings.extend(r['findings'])
            
            # Unique findings
            unique_findings = list(set(
                f['pattern'] for f in all_findings
            ))
            
            return {
                'success': True,
                'video_title': title,
                'duration': duration,
                'total_frames_analyzed': len(results),
                'frames_with_scam': len(scam_frames),
                'scam_percentage': round(len(scam_frames) / max(len(results), 1) * 100, 1),
                'unique_findings': unique_findings,
                'frame_results': results,
                'combined_findings': all_findings
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'total_frames_analyzed': 0,
                'frames_with_scam': 0,
                'scam_percentage': 0,
                'unique_findings': [],
                'frame_results': []
            }
    
    def _analyze_video_frames(self, video_path, sample_interval, duration):
        """Video ke frames analyze karo"""
        print(f"[DEBUG] Opening: {video_path}")
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            print("[DEBUG] OpenCV failed to open video")
            return []
        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        results = []
        frame_count = 0
        
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            
            # Har sample_interval second par frame analyze karo
            current_time = frame_count / fps
            if int(current_time) % sample_interval == 0 and frame_count % int(fps) == 0:
                # Convert to PIL Image
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil_img = Image.fromarray(rgb_frame)
                
                # OCR
                text = pytesseract.image_to_string(pil_img, lang='eng+hin')
                
                # Check patterns
                findings = self._check_patterns(text)
                
                results.append({
                    'timestamp': int(current_time),
                    'text': text.strip()[:200],  # Limit text length
                    'text_length': len(text.strip()),
                    'findings': findings,
                    'scam_detected': len(findings) > 0
                })
            
            frame_count += 1
        
        cap.release()
        return results
    
    def _check_patterns(self, text):
        """Text mein scam patterns check karo"""
        if not text:
            return []
        
        text_lower = text.lower()
        findings = []
        seen_patterns = set()
        
        for pattern, category in self.scam_overlay_patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                # Duplicate avoid karo
                pattern_key = f"{category}:{pattern}"
                if pattern_key not in seen_patterns:
                    seen_patterns.add(pattern_key)
                    findings.append({
                        'pattern': pattern,
                        'category': category,
                        'matches': matches[:3],
                        'match_count': len(matches)
                    })
        
        return findings
    
    def analyze_batch(self, content_list, max_videos=5):
        """
        Multiple videos/images ko batch mein analyze karo.
        Sirf HIGH/CRITICAL risk wale content ke liye use karo.
        """
        results = []
        video_count = 0
        
        for content in content_list:
            if video_count >= max_videos:
                break
            
            url = content.get('url', '')
            risk_level = content.get('risk_analysis', {}).get('risk_level', 'LOW')
            
            # Sirf high risk videos ko analyze karo
            if risk_level in ['HIGH', 'CRITICAL'] and url:
                print(f"\n[VideoAnalyzer] Analyzing: {content.get('title', 'Unknown')[:60]}")
                
                if 'youtube.com' in url or 'youtu.be' in url:
                    result = self.analyze_video_url(url, sample_interval=20)
                    content['video_analysis'] = result
                    results.append(content)
                    video_count += 1
                    
                    if result['success']:
                        print(f"  Frames analyzed: {result['total_frames_analyzed']}")
                        print(f"  Scam frames: {result['frames_with_scam']}")
                        print(f"  Scam %: {result['scam_percentage']}%")
                        if result['unique_findings']:
                            print(f"  Findings: {result['unique_findings'][:5]}")
                    else:
                        print(f"  Error: {result.get('error', 'Unknown')}")
        
        return results


# Test function
def test_video_analyzer():
    analyzer = VideoFrameAnalyzer()
    
    # Test 1: Image URL se analyze
    print("\n=== Test 1: Sample text in image ===")
    # Simple test: ek temporary image banao
    from PIL import Image, ImageDraw, ImageFont
    
    img = Image.new('RGB', (400, 100), color='black')
    draw = ImageDraw.Draw(img)
    draw.text((10, 40), "Satta Matka Live | 100% Guaranteed Win", fill='white')
    
    result = analyzer.analyze_image(img)
    print(f"Scam detected: {result['scam_detected']}")
    print(f"Text: {result['extracted_text'][:80]}")
    if result['findings']:
        for f in result['findings'][:3]:
            print(f"  {f['category']}: {f['match_count']} matches")
    
    # Test 2: YouTube video
    print("\n=== Test 2: YouTube Video ===")
    test_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"  # Sample URL
    
    # Note: Actual analysis ke liye real video URL chahiye
    print("Skipping actual video download. Use analyze_video_url() with real URLs.")
    
    print("\n[+] Video analyzer ready!")
    return analyzer


if __name__ == '__main__':
    test_video_analyzer()
