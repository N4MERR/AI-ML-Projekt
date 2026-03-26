import requests
import re
import time
import base64
import csv
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

def scrape_github_regex(token: str, target_count: int = 500) -> None:
    """
    Scrapes unique Python regex patterns from GitHub.
    Validates compilation using the re module.
    Logs the exact count of scraped patterns in real-time.
    Saves the valid results to a CSV file.
    """
    headers = {"Authorization": f"token {token}"}
    regexes = set()
    page = 1

    logging.info(f"Starting scrape for {target_count} patterns...")

    try:
        while len(regexes) < target_count:
            search_url = f"https://api.github.com/search/code?q=re.compile+language:python&per_page=100&page={page}"
            response = requests.get(search_url, headers=headers)

            if response.status_code != 200:
                logging.warning(f"Error {response.status_code}: Waiting 60 seconds...")
                time.sleep(60)
                continue

            items = response.json().get("items", [])
            if not items:
                logging.info("No more items found.")
                break

            for item in items:
                if len(regexes) >= target_count:
                    break

                file_response = requests.get(item["url"], headers=headers)
                if file_response.status_code == 200:
                    try:
                        raw_content = file_response.json().get("content", "")
                        content = base64.b64decode(raw_content).decode('utf-8')
                        found = re.findall(r"re\.(?:compile|search|match)\(\s*r(['\"])(.*?)\1", content)

                        for _, pattern in found:
                            if len(pattern) > 5 and pattern not in regexes:
                                try:
                                    re.compile(pattern)
                                    regexes.add(pattern)
                                    logging.info(f"Scraped new pattern. Total: {len(regexes)}/{target_count}")
                                except Exception:
                                    pass
                    except Exception:
                        pass

                time.sleep(0.5)

            logging.info(f"Page {page} complete.")
            page += 1
            time.sleep(2)

    except KeyboardInterrupt:
        logging.warning("Stopping and saving progress...")

    with open("scraped_regexes1.csv", "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["regex_pattern"])
        for pattern in regexes:
            writer.writerow([pattern])

    logging.info(f"Done. Saved {len(regexes)} patterns to scraped_regexes1.csv")

if __name__ == "__main__":
    TOKEN = "github_api_token"
    scrape_github_regex(TOKEN)