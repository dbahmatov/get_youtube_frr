#!/usr/bin/env python3
"""
YouTube Video Server ASN Analyzer
Analyzes YouTube video requests to extract server addresses and ASN information
"""

import re
import json
import socket
import datetime
import random
import time
import requests
from urllib.parse import urlparse, parse_qs, unquote, quote_plus
from typing import Dict, List, Optional

class YouTubeASNAnalyzer:
    def __init__(self):
        self.asn_cache = {}
        self.http = requests.Session()

    def _extract_json_object_at(self, text: str, start: int) -> Optional[Dict]:
        """Extract a JSON object starting at the first '{' at/after start, using brace balancing."""
        open_brace = text.find('{', start)
        if open_brace == -1:
            return None

        depth = 0
        in_string = False
        escaped = False

        for i in range(open_brace, len(text)):
            ch = text[i]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    candidate = text[open_brace:i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        return None

        return None

    def extract_player_response_from_watch_html(self, html: str) -> Optional[Dict]:
        """Extract `ytInitialPlayerResponse` JSON from a YouTube watch page HTML."""
        markers = [
            "var ytInitialPlayerResponse =",
            "ytInitialPlayerResponse =",
        ]
        for marker in markers:
            idx = html.find(marker)
            if idx == -1:
                continue
            obj = self._extract_json_object_at(html, idx + len(marker))
            if isinstance(obj, dict):
                return obj
        return None

    def extract_streaming_urls_from_player_response(self, player_response: Dict) -> List[str]:
        """Extract googlevideo playback URLs from `streamingData` (url or signatureCipher/cipher)."""
        urls: List[str] = []
        streaming = player_response.get("streamingData") or {}
        for key in ("serverAbrStreamingUrl", "hlsManifestUrl", "dashManifestUrl"):
            val = streaming.get(key)
            if isinstance(val, str) and val:
                urls.append(val)
        candidates = (streaming.get("formats") or []) + (streaming.get("adaptiveFormats") or [])

        for fmt in candidates:
            if not isinstance(fmt, dict):
                continue
            if "url" in fmt and isinstance(fmt["url"], str):
                urls.append(fmt["url"])
                continue

            cipher = fmt.get("signatureCipher") or fmt.get("cipher")
            if not cipher or not isinstance(cipher, str):
                continue

            parsed = parse_qs(cipher)
            cipher_url = parsed.get("url", [None])[0]
            if cipher_url and isinstance(cipher_url, str):
                urls.append(unquote(cipher_url))

        # De-dup while preserving order
        seen = set()
        unique = []
        for u in urls:
            if u not in seen:
                unique.append(u)
                seen.add(u)
        return unique

    def fetch_watch_page_html(self, video_id_or_url: str) -> str:
        """Fetch YouTube watch page HTML (browser-like) to discover streaming URLs dynamically."""
        video_id_or_url = video_id_or_url.strip()
        if "://" in video_id_or_url:
            watch_url = video_id_or_url
        else:
            watch_url = f"https://www.youtube.com/watch?v={video_id_or_url}"

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/136.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = self.http.get(watch_url, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.text

    def fetch_search_results_html(self, query: str) -> str:
        """Fetch YouTube search results HTML for a query."""
        url = f"https://www.youtube.com/results?search_query={quote_plus(query)}"
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/136.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = self.http.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.text

    def extract_video_ids_from_html(self, html: str) -> List[str]:
        """Extract YouTube video IDs from HTML containing watch links."""
        ids = re.findall(r'watch\?v=([A-Za-z0-9_-]{11})', html)
        # De-dup while preserving order
        seen = set()
        unique = []
        for vid in ids:
            if vid not in seen:
                unique.append(vid)
                seen.add(vid)
        return unique

    def collect_random_video_ids_via_search(
        self,
        count: int,
        base_query: Optional[str] = None,
        max_search_pages: int = 10,
        delay_sec: float = 0.2,
    ) -> List[str]:
        """Collect candidate video IDs by hitting YouTube search pages (no API key)."""
        if count <= 0:
            return []

        seed_queries = [
            "music",
            "news",
            "podcast",
            "tutorial",
            "gaming",
            "review",
            "live",
            "спорт",
            "обзор",
            "влог",
            "смешное",
        ]

        pool: List[str] = []
        seen = set()

        for _ in range(max_search_pages):
            if base_query:
                q = f"{base_query.strip()} {random.randint(1, 10_000)}"
            else:
                q = f"{random.choice(seed_queries)} {random.randint(1, 10_000)}"

            try:
                html = self.fetch_search_results_html(q)
            except requests.RequestException:
                time.sleep(delay_sec)
                continue

            ids = self.extract_video_ids_from_html(html)
            random.shuffle(ids)
            for vid in ids:
                if vid in seen:
                    continue
                pool.append(vid)
                seen.add(vid)
                if len(pool) >= count * 5:
                    break

            if len(pool) >= count:
                break

            time.sleep(delay_sec)

        if len(pool) <= count:
            return pool
        return random.sample(pool, k=count)

    def _finalize_asn_summary(self, asn_summary: Dict[str, Dict]) -> List[Dict]:
        """Convert internal ASN summary sets to printable lists with counts"""
        items = []
        for key, entry in asn_summary.items():
            ips = sorted(entry['ips'])
            hostnames = sorted(entry['hostnames'])
            items.append({
                'key': key,
                'asn': entry.get('asn'),
                'org': entry.get('org', 'Unknown'),
                'ip_count': len(ips),
                'hostname_count': len(hostnames),
                'ips': ips,
                'hostnames': hostnames
            })

        items.sort(key=lambda item: (-item['ip_count'], item['key']))
        return items
    
    def extract_video_urls(self, fetch_code: str) -> List[str]:
        """Extract video URLs from fetch() code"""
        urls = []
        
        # Find fetch() calls with URLs
        fetch_pattern = r'fetch\s*\(\s*["\']([^"\']+)["\']'
        matches = re.findall(fetch_pattern, fetch_code)
        
        for match in matches:
            if 'googlevideo.com' in match or 'youtube.com' in match:
                urls.append(match)
        
        return urls
    
    def parse_youtube_url(self, url: str) -> Dict:
        """Parse YouTube video URL and extract server info"""
        parsed = urlparse(url)
        
        info = {
            'full_url': url,
            'hostname': parsed.hostname,
            'path': parsed.path,
            'params': parse_qs(parsed.query)
        }
        
        # Extract server details from hostname
        if parsed.hostname:
            hostname = parsed.hostname
            if hostname.endswith("googlevideo.com"):
                # Common format: rr2---sn-8ph2xajvh-n8vl.googlevideo.com (single subdomain)
                subdomain = hostname.split(".", 1)[0]
                if "---" in subdomain:
                    server_id, node_id = subdomain.split("---", 1)
                    info["server_id"] = server_id
                    info["node_id"] = node_id
                else:
                    info["server_id"] = subdomain
        
        return info
    
    def resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses"""
        try:
            result = socket.getaddrinfo(hostname, None)
            ips = list(set([addr[4][0] for addr in result]))
            return ips
        except socket.gaierror as e:
            print(f"DNS resolution failed for {hostname}: {e}")
            return []
    
    def get_asn_info(self, ip: str) -> Optional[Dict]:
        """Get ASN information for an IP address"""
        if ip in self.asn_cache:
            return self.asn_cache[ip]

        time.sleep(0.2)  # ipinfo.io free tier: 50k req/month
        try:
            # Using ipinfo.io API (free tier)
            response = self.http.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                asn_info = {
                    'ip': ip,
                    'org': data.get('org', 'Unknown'),
                    'asn': None,
                    'isp': data.get('org', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown')
                }
                
                # Extract ASN number from org field (format: "AS15169 Google LLC")
                org = data.get('org', '')
                asn_match = re.match(r'AS(\d+)', org)
                if asn_match:
                    asn_info['asn'] = int(asn_match.group(1))
                
                self.asn_cache[ip] = asn_info
                return asn_info
            
        except requests.RequestException as e:
            print(f"Failed to get ASN info for {ip}: {e}")
        
        return None
    
    def get_asn_whois(self, asn: int) -> Optional[Dict]:
        """Get detailed ASN information via whois"""
        time.sleep(0.2)  # ipinfo.io free tier: 50k req/month
        try:
            # Using ipinfo.io ASN API
            response = self.http.get(f"https://ipinfo.io/AS{asn}/json", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'asn': asn,
                    'name': data.get('name', 'Unknown'),
                    'domain': data.get('domain', 'Unknown'),
                    'type': data.get('type', 'Unknown'),
                    'country': data.get('country', 'Unknown')
                }
        except requests.RequestException as e:
            print(f"Failed to get ASN whois for AS{asn}: {e}")
        
        return None
    
    def analyze_urls(self, urls: List[str]) -> Dict:
        """Analyze a list of YouTube/googlevideo URLs"""
        results = {
            'analysis_context': {
                'host': socket.gethostname(),
                'resolved_at': datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            },
            'urls_found': len(urls),
            'servers': [],
            'unique_asns': set(),
            'summary': {},
            'asn_summary': {}
        }
        
        for url in urls:
            url_info = self.parse_youtube_url(url)
            hostname = url_info.get('hostname')
            
            if not hostname:
                continue
            
            print(f"\nAnalyzing: {hostname}")
            
            # Resolve IPs
            ips = self.resolve_hostname(hostname)
            print(f"Resolved IPs: {ips}")
            
            server_info = {
                'hostname': hostname,
                'url_info': url_info,
                'ips': ips,
                'asn_info': []
            }
            
            # Get ASN info for each IP
            for ip in ips:
                asn_info = self.get_asn_info(ip)
                if asn_info:
                    server_info['asn_info'].append(asn_info)
                    if asn_info['asn']:
                        results['unique_asns'].add(asn_info['asn'])
                    print(f"  {ip} -> AS{asn_info.get('asn', 'Unknown')} ({asn_info.get('org', 'Unknown')})")

                    asn_key = f"AS{asn_info['asn']}" if asn_info.get('asn') else "AS-UNKNOWN"
                    if asn_key not in results['asn_summary']:
                        results['asn_summary'][asn_key] = {
                            'asn': asn_info.get('asn'),
                            'org': asn_info.get('org', 'Unknown'),
                            'ips': set(),
                            'hostnames': set()
                        }
                    results['asn_summary'][asn_key]['ips'].add(ip)
                    results['asn_summary'][asn_key]['hostnames'].add(hostname)
            
            results['servers'].append(server_info)
        
        # Generate summary
        results['unique_asns'] = list(results['unique_asns'])
        results['summary'] = {
            'total_servers': len(results['servers']),
            'unique_asns_count': len(results['unique_asns']),
            'asn_details': []
        }
        results['asn_summary'] = self._finalize_asn_summary(results['asn_summary'])
        
        # Get detailed ASN information
        for asn in results['unique_asns']:
            asn_details = self.get_asn_whois(asn)
            if asn_details:
                results['summary']['asn_details'].append(asn_details)
        
        return results

    def analyze_fetch_request(self, fetch_code: str) -> Dict:
        """Analyze the complete fetch() request code (extracts URLs first)."""
        urls = self.extract_video_urls(fetch_code)
        return self.analyze_urls(urls)

    def analyze_watch_page(self, video_id_or_url: str) -> Dict:
        """Fetch a YouTube watch page and analyze streaming URLs (host determined dynamically by YouTube)."""
        html = self.fetch_watch_page_html(video_id_or_url)
        player = self.extract_player_response_from_watch_html(html)
        if not player:
            return self.analyze_urls([])
        urls = self.extract_streaming_urls_from_player_response(player)

        # De-dup by hostname to avoid repeated DNS/IP lookups for the same host
        seen_hosts: set = set()
        unique_urls: List[str] = []
        for u in urls:
            host = urlparse(u).hostname or u
            if host not in seen_hosts:
                unique_urls.append(u)
                seen_hosts.add(host)

        return self.analyze_urls(unique_urls)

    def analyze_random_videos(
        self,
        count: int = 5,
        base_query: Optional[str] = None,
        per_video_delay_sec: float = 0.5,
        max_search_pages: int = 10,
    ) -> Dict:
        """Pick random videos via search and analyze their actual streaming hosts on this machine."""
        video_ids = self.collect_random_video_ids_via_search(
            count=max(1, count * 3),
            base_query=base_query,
            max_search_pages=max_search_pages,
        )

        urls: List[str] = []
        ok_video_ids: List[str] = []

        for vid in video_ids:
            if len(ok_video_ids) >= count:
                break
            try:
                html = self.fetch_watch_page_html(vid)
            except requests.RequestException:
                time.sleep(per_video_delay_sec)
                continue

            player = self.extract_player_response_from_watch_html(html)
            if not player:
                time.sleep(per_video_delay_sec)
                continue

            extracted = self.extract_streaming_urls_from_player_response(player)
            extracted = [u for u in extracted if "googlevideo.com" in u]
            if not extracted:
                time.sleep(per_video_delay_sec)
                continue

            urls.append(extracted[0])
            ok_video_ids.append(vid)
            time.sleep(per_video_delay_sec)

        # De-dup by hostname to avoid repeated DNS/IP lookups
        seen_hosts = set()
        unique_urls: List[str] = []
        for u in urls:
            host = urlparse(u).hostname or u
            if host in seen_hosts:
                continue
            unique_urls.append(u)
            seen_hosts.add(host)

        results = self.analyze_urls(unique_urls)
        results["analysis_context"]["videos_requested"] = count
        results["analysis_context"]["videos_collected"] = len(video_ids)
        results["analysis_context"]["videos_analyzed"] = len(ok_video_ids)
        results["analysis_context"]["urls_collected"] = len(urls)
        results["analysis_context"]["urls_analyzed"] = len(unique_urls)
        results["analysis_context"]["hosts_analyzed"] = len(seen_hosts)
        results["analysis_context"]["video_ids"] = ok_video_ids
        if base_query:
            results["analysis_context"]["base_query"] = base_query
        return results
    
    def print_results(self, results: Dict):
        """Print analysis results in a readable format"""
        print("\n" + "="*60)
        print("YOUTUBE VIDEO SERVER ASN ANALYSIS")
        print("="*60)

        context = results.get('analysis_context', {})
        if context:
            print(f"\nAnalysis host: {context.get('host', 'Unknown')}")
            print(f"Resolved at (UTC): {context.get('resolved_at', 'Unknown')}")
            if "videos_analyzed" in context:
                base_query = context.get("base_query")
                query_str = f", base query: {base_query}" if base_query else ""
                print(
                    f"Videos: {context.get('videos_analyzed', 0)} analyzed "
                    f"({context.get('videos_collected', 0)} collected, {context.get('videos_requested', 0)} requested){query_str}"
                )
                if "urls_analyzed" in context:
                    print(
                        f"URLs: {context.get('urls_analyzed', 0)} analyzed "
                        f"({context.get('urls_collected', 0)} collected)"
                    )

        print(f"\nSUMMARY:")
        print(f"  Total URLs found: {results['urls_found']}")
        print(f"  Total servers: {results['summary']['total_servers']}")
        print(f"  Unique ASNs: {results['summary']['unique_asns_count']}")

        print(f"\nASN LIST (UNIQUE):")
        if results.get('asn_summary'):
            asn_keys = [entry['key'] for entry in results['asn_summary']]
            print(f"  {', '.join(asn_keys)}")
        else:
            print("  None found (no resolvable YouTube hosts).")

        print(f"\nASNS USED FOR YOUTUBE ON THIS HOST:")
        if results.get('asn_summary'):
            for entry in results['asn_summary']:
                print(f"  {entry['key']} - {entry['org']} ({entry['ip_count']} IPs, {entry['hostname_count']} hostnames)")
        else:
            print("  None found (no resolvable YouTube hosts).")

        print(f"\nASN DETAILS:")
        for asn_detail in results['summary']['asn_details']:
            print(f"  AS{asn_detail['asn']} - {asn_detail['name']}")
            print(f"    Domain: {asn_detail['domain']}")
            print(f"    Type: {asn_detail['type']}")
            print(f"    Country: {asn_detail['country']}")
        
        print(f"\nDETAILED SERVER INFORMATION:")
        for i, server in enumerate(results['servers'], 1):
            print(f"\n  Server {i}: {server['hostname']}")
            
            if 'server_id' in server['url_info']:
                print(f"    Server ID: {server['url_info']['server_id']}")
            
            print(f"    IP Addresses:")
            for asn_info in server['asn_info']:
                print(f"      {asn_info['ip']} -> AS{asn_info.get('asn', 'N/A')} ({asn_info.get('org', 'Unknown')})")
                print(f"        Location: {asn_info.get('city', 'Unknown')}, {asn_info.get('country', 'Unknown')}")

def main():
    """Main function to run the analyzer"""
    
    # Sample YouTube fetch code (replace with your actual fetch code)
    sample_fetch_code = '''
    fetch("https://YOUR_DYNAMIC_GOOGLEVIDEO_HOST.googlevideo.com/videoplayback?...", {
      "headers": {
        "accept": "*/*",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "cross-site"
      },
      "referrer": "https://www.youtube.com/",
      "method": "POST"
    });
    '''
    
    analyzer = YouTubeASNAnalyzer()
    
    print("YouTube Video Server ASN Analyzer")
    print("This script analyzes YouTube fetch requests to identify server ASNs")
    
    choice = input(
        "\n1. Analyze sample data\n"
        "2. Analyze custom fetch code\n"
        "3. Fetch YouTube watch page and analyze (dynamic host)\n"
        "4. Analyze random videos via search (dynamic host)\n"
        "Choice (1-4): "
    ).strip()
    
    if choice == "4":
        count_raw = input("\nHow many random videos to analyze? (default: 5): ").strip()
        query = input("Optional base search query (empty = random): ").strip()
        delay_raw = input("Delay between videos in seconds (default: 0.5): ").strip()

        count = int(count_raw) if count_raw else 5
        delay = float(delay_raw) if delay_raw else 0.5
        base_query = query if query else None

        results = analyzer.analyze_random_videos(
            count=count,
            base_query=base_query,
            per_video_delay_sec=delay,
        )
        analyzer.print_results(results)
    elif choice == "3":
        video = input("\nEnter YouTube video URL or video id: ").strip()
        results = analyzer.analyze_watch_page(video)
        analyzer.print_results(results)
    elif choice == "2":
        print("\nPaste your fetch() code (press Ctrl+D or Ctrl+Z when done):")
        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass
        
        fetch_code = '\n'.join(lines)
        results = analyzer.analyze_fetch_request(fetch_code)
        analyzer.print_results(results)
    else:
        results = analyzer.analyze_fetch_request(sample_fetch_code)
        analyzer.print_results(results)
    
    # Option to save results to JSON
    save_choice = input("\nSave results to JSON file? (y/n): ").strip().lower()
    if save_choice == 'y':
        filename = input("Enter filename (default: youtube_asn_results.json): ").strip()
        if not filename:
            filename = "youtube_asn_results.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"Results saved to {filename}")

if __name__ == "__main__":
    main()
