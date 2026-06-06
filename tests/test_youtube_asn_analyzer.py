import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from youtube_asn_analyzer import YouTubeASNAnalyzer


class TestYouTubeASNAnalyzer(unittest.TestCase):
    def test_extract_video_ids_from_html_dedup(self):
        analyzer = YouTubeASNAnalyzer()
        html = (
            '<a href="/watch?v=AAAAAAAAAAA">a</a>'
            '<a href="/watch?v=BBBBBBBBBBB">b</a>'
            '<a href="/watch?v=AAAAAAAAAAA">a2</a>'
        )
        self.assertEqual(analyzer.extract_video_ids_from_html(html), ["AAAAAAAAAAA", "BBBBBBBBBBB"])

    def test_extract_streaming_urls_includes_server_abr(self):
        analyzer = YouTubeASNAnalyzer()
        player = {
            "streamingData": {
                "serverAbrStreamingUrl": "https://rr9---sn-abr.googlevideo.com/videoplayback?id=1",
                "formats": [],
                "adaptiveFormats": [],
            }
        }
        urls = analyzer.extract_streaming_urls_from_player_response(player)
        self.assertEqual(urls, ["https://rr9---sn-abr.googlevideo.com/videoplayback?id=1"])

    def test_extract_streaming_urls_from_player_response_direct_url(self):
        analyzer = YouTubeASNAnalyzer()
        player = {
            "streamingData": {
                "formats": [{"url": "https://rr1---sn-test.googlevideo.com/videoplayback?id=1"}],
                "adaptiveFormats": [],
            }
        }
        urls = analyzer.extract_streaming_urls_from_player_response(player)
        self.assertEqual(urls, ["https://rr1---sn-test.googlevideo.com/videoplayback?id=1"])

    def test_extract_streaming_urls_from_player_response_signature_cipher(self):
        analyzer = YouTubeASNAnalyzer()
        player = {
            "streamingData": {
                "formats": [],
                "adaptiveFormats": [
                    {
                        "signatureCipher": (
                            "url=https%3A%2F%2Frr2---sn-8ph2xajvh-n8vl.googlevideo.com%2Fvideoplayback%3Fid%3D1"
                            "&sp=sig&s=ENCRYPTED"
                        )
                    }
                ],
            }
        }
        urls = analyzer.extract_streaming_urls_from_player_response(player)
        self.assertEqual(
            urls,
            ["https://rr2---sn-8ph2xajvh-n8vl.googlevideo.com/videoplayback?id=1"],
        )

    def test_parse_youtube_url_server_and_node(self):
        analyzer = YouTubeASNAnalyzer()
        info = analyzer.parse_youtube_url(
            "https://rr2---sn-8ph2xajvh-n8vl.googlevideo.com/videoplayback?id=1"
        )
        self.assertEqual(info.get("server_id"), "rr2")
        self.assertEqual(info.get("node_id"), "sn-8ph2xajvh-n8vl")


if __name__ == "__main__":
    unittest.main()
