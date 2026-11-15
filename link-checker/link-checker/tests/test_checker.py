import hashlib
import os
import tempfile
import unittest

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")

from checker import analyze_url, scan_file, database as db  # noqa: E402


class UrlTests(unittest.TestCase):
    def score(self, url):
        return analyze_url(url)["score"]

    def test_deceptive_links_are_flagged(self):
        for url in [
            "https://facebook.com.secure-login.example/verify",
            "http://faceb00k-login.example/",
            "https://gooogle.example/account",
            "http://paypa1-secure.top/login",
            "http://192.168.1.5/paypal/login",
            "https://facebook.com@evil.example/",
            "http://xn--fcebook-8va.example/",
        ]:
            self.assertGreaterEqual(self.score(url), 35, url)

    def test_legit_links_stay_low(self):
        for url in ["https://www.facebook.com/", "https://accounts.google.com/signin",
                    "https://github.com/", "https://example.com"]:
            self.assertLess(self.score(url), 35, url)

    def test_db_match(self):
        db.insert_threats([("bad.example/x", "bad.example", "demo", 0)])
        self.assertEqual(analyze_url("https://bad.example/x")["score"], 100)
        self.assertGreaterEqual(analyze_url("https://bad.example/other")["score"], 35)


class FileTests(unittest.TestCase):
    def test_fake_image_that_is_exe(self):
        self.assertGreaterEqual(scan_file("photo.png", b"MZ" + b"\x00" * 100)["score"], 50)

    def test_double_extension(self):
        self.assertGreaterEqual(scan_file("invoice.pdf.exe", b"MZ\x90\x00")["score"], 70)

    def test_known_hash(self):
        blob = b"just a test blob"
        db.add_hash(hashlib.sha256(blob).hexdigest(), "test blob")
        self.assertEqual(scan_file("a.txt", blob)["score"], 100)

    def test_clean_png(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50 + b"IEND\xaeB`\x82"
        self.assertLess(scan_file("ok.png", png)["score"], 35)

    def test_script_inside_image(self):
        jpg = b"\xff\xd8\xff\xe0" + b"<?php system($_GET['c']); ?>" + b"\xff\xd9"
        self.assertGreaterEqual(scan_file("cat.jpg", jpg)["score"], 35)


if __name__ == "__main__":
    unittest.main()
