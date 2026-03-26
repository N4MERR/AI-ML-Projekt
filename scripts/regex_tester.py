"""
Module for testing regex patterns from a single cleaned CSV file for
ReDoS vulnerabilities using the regexploit CLI tool.
"""

import csv
import subprocess
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

class RegexVulnerabilityTester:
    """
    Reads regex patterns from a clean CSV file, tests each for ReDoS
    vulnerabilities using regexploit, and saves the results.
    """

    def __init__(self, input_file: str, output_file: str):
        """
        Initializes the tester with input and output filenames.
        """
        self.input_file = input_file
        self.output_file = output_file
        self.logger = logging.getLogger(__name__)

    def is_vulnerable(self, pattern: str) -> bool:
        """
        Runs the regexploit CLI tool against a single regex string.
        Returns True if vulnerable to ReDoS, False otherwise.
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
            self.logger.warning(f"Timeout expired for pattern: {pattern}")
            return True
        except FileNotFoundError:
            self.logger.error("The 'regexploit' command was not found.")
            raise RuntimeError("Please install regexploit via 'pip install regexploit'.")

    def process_file(self):
        """
        Reads the cleaned input CSV, tests each regex, and writes the
        pattern along with its vulnerability status to the output CSV.
        """
        self.logger.info(f"Starting vulnerability tests from {self.input_file}.")

        with open(self.input_file, 'r', encoding='utf-8') as infile, \
             open(self.output_file, 'w', encoding='utf-8', newline='') as outfile:

            reader = csv.DictReader(infile)
            writer = csv.writer(outfile)
            writer.writerow(["regex_pattern", "is_vulnerable"])

            for i, row in enumerate(reader, 1):
                pattern = row["regex_pattern"]
                vulnerable = self.is_vulnerable(pattern)
                writer.writerow([pattern, vulnerable])

                if i % 10 == 0:
                    self.logger.info(f"Progress: {i} regexes tested.")

        self.logger.info(f"Testing complete. Results saved to {self.output_file}")


if __name__ == "__main__":
    """
    Main execution block to test a single cleaned CSV file.
    """
    tester = RegexVulnerabilityTester("scraped_regexes.csv", "scraped_regexes.csv")
    tester.process_file()