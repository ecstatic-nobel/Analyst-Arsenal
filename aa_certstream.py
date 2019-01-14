#!/usr/bin/python
"""
Description:
- Stream CT logs via Certstream
- Score and add suspicious domains to a queue while other domains continue to be scored
- Simultaneously make requests to the domains in the queue to search for predefined file extensions
- Recursively download the site when an open directory is found hosting a file with a particular extension

Optional arguments:
- --file-dir     : Directory to use for interesting files detected (default: ./InterestingFiles/)
- --kit-dir      : Directory to use for phishing kits detected (default: ./KitJackinSeason/)
- --level        : Recursion depth (default=1, infinite=0)
- --log-nc       : File to store domains that have not been checked
- --quiet        : Don't show wget output
- --score        : Minimum score to trigger a session (Default: 75)
- --threads      : Numbers of threads to spawn
- --timeout      : Set time to wait for a connection
- --tor          : Download files via the Tor network
- --verbose      : Show domains being scored
- --very-verbose : Show error messages

Usage:
```
python aa_certstream.py [--file-dir] [--kit-dir] [--level] [--log-nc] [--quiet] [--score] [--threads] [--timeout] [--tor] [--verbose] [--very-verbose]
```

Debugger: open("/tmp/aa.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import certstream
from termcolor import colored, cprint
import tqdm

import commons


# Parse Arguments
parser = argparse.ArgumentParser(
    description="Attempt to detect phishing kits and open directories via Certstream."
)
parser.add_argument("--file-dir",
                    dest="file_dir",
                    default="./InterestingFile/",
                    required=False,
                    help="Directory to use for interesting files detected (default: ./InterestingFiles/)")
parser.add_argument("--kit-dir",
                    dest="kit_dir",
                    default="./KitJackinSeason/",
                    required=False,
                    help="Directory to use for phishing kits detected (default: ./KitJackinSeason/)")
parser.add_argument("--level",
                    dest="level",
                    default=1,
                    required=False,
                    type=str,
                    help="Directory depth (default=1, infinite=0")
parser.add_argument("--log-nc",
                    dest="log_nc",
                    required=False,
                    type=str,
                    help="File to store domains that have not been checked")
parser.add_argument("--quiet",
                    dest="quiet",
                    action="store_true",
                    required=False,
                    help="Don't show wget output")
parser.add_argument("--score",
                    dest="score",
                    default=75,
                    required=False,
                    type=int,
                    help="Minimum score to trigger a session (Default: 75)")
parser.add_argument("--threads",
                    dest="threads",
                    default=3,
                    required=False,
                    type=int,
                    help="Numbers of threads to spawn")
parser.add_argument("--timeout",
                    dest="timeout",
                    default=30,
                    required=False,
                    type=int,
                    help="Set time to wait for a connection")
parser.add_argument("--tor",
                    dest="tor",
                    action="store_true",
                    required=False,
                    help="Download files over the Tor network")
parser.add_argument("--verbose",
                    dest="verbose",
                    action="store_true",
                    required=False,
                    help="Show domains being scored")
parser.add_argument("--very-verbose",
                    dest="very_verbose",
                    action="store_true",
                    required=False,
                    help="Show error messages")
args   = parser.parse_args()
uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

# Fix directory names
args = commons.fix_directory(args)

tqdm.tqdm.monitor_interval = 0

def callback(message, context):
    """Callback handler for certstream events."""
    if message["message_type"] == "certificate_update":
        all_domains = message["data"]["leaf_cert"]["all_domains"]

        if len(all_domains) == 0:
            return
        else:
            domain = all_domains[0]

        if domain.startswith("*."):
            domain = domain[2:]

        match_found = False
        for exclusion in exclusions:
            if exclusion.search(domain):
                match_found = True
                break
        
        if match_found:
            return

        pbar.update(1)

        score = commons.score_domain(suspicious, domain.lower(), args)

        if "Let's Encrypt" in message["data"]["chain"][0]["subject"]["aggregated"]:
            score += 10
        
        if score < args.score:
            if args.log_nc:
                with open(args.log_nc, "a") as log_nc:
                    log_nc.write("{}\n".format(domain))
            return

        if args.verbose:
            if score >= 120:
                tqdm.tqdm.write(
                    "{}: {} (score={})".format(
                        commons.message_header("critical"),
                        colored(domain, "red", attrs=["underline", "bold"]),
                        score
                    )
                )
            elif score >= 90:
                tqdm.tqdm.write(
                    "{}: {} (score={})".format(
                        commons.message_header("suspicious"),
                        colored(domain, "yellow", attrs=["underline"]),
                        score
                    )
                )
            elif score >= args.score:
                tqdm.tqdm.write(
                    "{}: {} (score={})".format(
                        commons.message_header("score"),
                        colored(domain, "cyan", attrs=["underline"]),
                        score
                    )
                )

        url = "https://{}".format(domain)

        if not url in list(url_queue.queue):
            url_queue.put(url)

            with open("queue_file.txt", "a") as queue_state:
                queue_state.write("{}\n".format(url))

def on_open(instance):
    """Instance is the CertStreamClient instance that was opened"""
    print(colored("Connection successfully established!\n", "yellow", attrs=["bold"]))

    if os.path.exists("queue_file.txt"):
        try:
            with open("queue_file.txt", "r") as queue_state:
                urls = queue_state.read().splitlines()

                if len(urls) > 0:
                    print(colored("Previous queue state found. Reloading...\n", "yellow", attrs=["bold"]))

                for url in urls:
                    url_queue.put(url)
        except Exception as err:
            commons.failed_message(args, err, None)

    if "pbar" not in globals():
        global pbar
        pbar = tqdm.tqdm(desc="certificate_update", unit="cert")
    return

def main():
    """ """
    global exclusions
    global suspicious
    global url_queue

    # Check if output directories exist
    commons.check_path(args)

    # Print start messages
    commons.show_summary(args)
    commons.show_networking(args, uagent)

    # Read suspicious.yaml and external.yaml
    suspicious = commons.read_externals()

    # Recompile exclusions
    exclusions = commons.recompile_exclusions()

    # Create queues
    url_queue = commons.create_queue("url_queue")

    # Create threads
    commons.UrlQueueManager(args, url_queue, uagent)

    # Listen for events via Certstream
    print(colored("Connecting to Certstream...\n", "yellow", attrs=["bold"]))
    certstream.listen_for_events(
        message_callback=callback,
        url="wss://certstream.calidog.io",
        on_open=on_open
    )

if __name__ == "__main__":
    main()
