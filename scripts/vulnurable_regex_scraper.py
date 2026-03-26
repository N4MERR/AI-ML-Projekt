"""
Module for scraping regular expressions from GitHub and immediately testing them
for ReDoS vulnerabilities. Utilizes multithreading to speed up the testing process
and calculates search queries dynamically by file size to bypass the 1,000-result API limit
and continuously search until the target count is reached.
"""

import requests
import re
import time
import base64
import subprocess
import csv
import logging
import sys
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)


class VulnerableRegexScraper:
    """
    Scrapes Python files on GitHub for regex patterns, tests them concurrently using regexploit,
    and appends vulnerable ones to a CSV file. Bypasses API limits via continuous size-range generation.
    """

    def __init__(self, token: str, output_file: str):
        """
        Initializes the scraper. If the output file exists, it appends; otherwise, it creates it with headers.
        """
        self.token = token
        self.headers = {"Authorization": f"token {self.token}"}
        self.output_file = output_file
        self.logger = logging.getLogger(__name__)
        self.seen_patterns = set()
        self.vulnerable_found = 0
        self.target_count = 0
        self.lock = threading.Lock()

        file_exists = os.path.isfile(self.output_file)
        with open(self.output_file, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            if not file_exists or os.path.getsize(self.output_file) == 0:
                writer.writerow(["regex_pattern", "is_vulnerable"])

    def is_vulnerable(self, pattern: str) -> bool:
        """
        Tests a single regex pattern using the regexploit CLI tool.
        Returns True if the pattern is vulnerable to ReDoS.
        """
        try:
            result = subprocess.run(
                ['regexploit'],
                input=pattern,
                text=True,
                encoding='utf-8',
                errors='replace',
                capture_output=True,
                timeout=2
            )
            output = result.stdout.strip() if result.stdout else ""
            return len(output) > 0
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Timeout expired (potential severe ReDoS) for pattern: {pattern}")
            return True
        except FileNotFoundError:
            self.logger.error("The 'regexploit' command was not found.")
            raise RuntimeError("Please install regexploit via 'pip install regexploit'.")

    def append_to_csv(self, pattern: str):
        """
        Appends a verified vulnerable pattern to the output CSV file safely using a thread lock.
        """
        with self.lock:
            with open(self.output_file, 'a', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([pattern, "True"])

    def process_item(self, item: dict):
        """
        Thread worker function. Fetches a single file's content, extracts regexes,
        verifies they are valid regular expressions, tests them, and saves vulnerable ones.
        """
        if self.vulnerable_found >= self.target_count:
            return

        try:
            file_res = requests.get(item["url"], headers=self.headers, timeout=10)

            if file_res.status_code in [403, 429]:
                reset_time = int(file_res.headers.get("X-RateLimit-Reset", time.time() + 60))
                sleep_duration = max(reset_time - int(time.time()), 5)
                self.logger.warning(f"Thread Rate Limit! Sleeping {sleep_duration}s.")
                time.sleep(sleep_duration)
                return

            if file_res.status_code == 200:
                content_b64 = file_res.json().get("content", "")
                content = base64.b64decode(content_b64).decode('utf-8', errors='ignore')

                found = re.findall(r"re\.(?:compile|search|match)\(\s*r(['\"])(.*?)\1", content)

                for _, p in found:
                    if self.vulnerable_found >= self.target_count:
                        break

                    if len(p) > 5:
                        try:
                            re.compile(p)
                        except re.error:
                            continue

                        with self.lock:
                            if p in self.seen_patterns:
                                continue
                            self.seen_patterns.add(p)

                        if self.is_vulnerable(p):
                            self.append_to_csv(p)
                            with self.lock:
                                self.vulnerable_found += 1
                                current_found = self.vulnerable_found
                            self.logger.info(f"Found vulnerable regex! Total so far: {current_found}/{self.target_count}")
        except Exception as e:
            self.logger.error(f"Error processing item: {e}")

    def scrape_and_test(self, target_vulnerable_count: int, start_page: int = 1, max_workers: int = 5):
        """
        Executes the scraping loop using dynamically calculated size-range increments
        to continuously bypass the 1,000-result limit until the target count is reached.
        """
        self.target_count = target_vulnerable_count
        self.logger.info(f"Starting scrape. Target: {self.target_count} vulnerable regexes.")

        min_size = 0
        max_size = 1000

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while self.vulnerable_found < self.target_count and min_size < 500000:
                page = start_page if min_size == 0 else 1

                while page <= 10:
                    if self.vulnerable_found >= self.target_count:
                        break

                    query = f"re.compile+language:python+size:{min_size}..{max_size}"
                    url = f"https://api.github.com/search/code?q={query}&per_page=100&page={page}"

                    self.logger.info(f"Query: size {min_size}-{max_size} | Page: {page}")
                    response = requests.get(url, headers=self.headers, timeout=15)

                    if response.status_code == 422:
                        self.logger.warning("Hit page limit for this size range. Moving to next range.")
                        break

                    if response.status_code in [403, 429]:
                        reset_time = int(response.headers.get("X-RateLimit-Reset", time.time() + 60))
                        sleep_duration = max(reset_time - int(time.time()), 10)
                        self.logger.warning(f"Search Rate Limit reached! Sleeping {sleep_duration}s.")
                        time.sleep(sleep_duration)
                        continue

                    if response.status_code != 200:
                        self.logger.error(f"API error: {response.status_code} - {response.text}")
                        break

                    data = response.json()
                    items = data.get("items", [])
                    if not items:
                        break

                    futures = [executor.submit(self.process_item, item) for item in items]

                    for future in as_completed(futures):
                        pass

                    page += 1
                    time.sleep(2)

                min_size = max_size + 1
                if min_size < 10000:
                    max_size = min_size + 1000
                elif min_size < 50000:
                    max_size = min_size + 5000
                else:
                    max_size = min_size + 20000

        self.logger.info(f"Done. Total vulnerable regexes: {self.vulnerable_found} in {self.output_file}.")


if __name__ == "__main__":
    MY_TOKEN = "github_api_token"
    TARGET_COUNT = 300
    START_PAGE = 11

    scraper = VulnerableRegexScraper(MY_TOKEN, "regexes_dangerous.csv")
    try:
        scraper.scrape_and_test(target_vulnerable_count=TARGET_COUNT, start_page=START_PAGE, max_workers=5)
    except KeyboardInterrupt:
        logging.info("Interrupted by user.")