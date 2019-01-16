#!/usr/bin/python
"""
Description:
- Download a list of newly registered domains from WHOIS Domain Search (whoisds.com)
- Score and add suspicious domains to a queue while other domains continue to be scored
- Simultaneously make requests to the domains in the queue to search for predefined file extensions
- Recursively download the site when an open directory is found hosting a file with a particular extension

1 positional argument needed:
- Delta : Number of days back to search (GMT)

Optional arguments:
- --dns-twist    : Check the twisted keywords found in dns_twisted.yaml
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
python aa_whoisds.py <DELTA> [--dns-twist] [--file-dir] [--kit-dir] [--level] [--log-nc] [--quiet] [--score] [--threads] [--timeout] [--tor] [--verbose] [--very-verbose]
```

Debugger: open("/tmp/aa.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
from termcolor import colored, cprint

import commons


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories via Certstream.")
parser.add_argument(dest="delta",
                    type=int,
                    help="Number of days back to search (GMT)")
parser.add_argument("--dns-twist",
                    dest="dns_twist",
                    action="store_true",
                    required=False,
                    help="Check the twisted keywords found in dns_twisted.yaml")
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

# Set threads to a minimum of 20 if using --dns-twist
if args.dns_twist and args.threads < 20:
    args.threads = 20

# Fix directory names
args = commons.fix_directory(args)

def main():
    """ """
    # Check if output directories exist
    commons.check_path(args)

    # Print start messages
    commons.show_summary(args)
    commons.show_networking(args, uagent)

    # Read suspicious.yaml
    commons.read_suspicious(args)

    # Recompile exclusions
    commons.recompile_exclusions()

    # Create queues
    domain_queue = commons.create_queue("domain_queue")
    url_queue    = commons.create_queue("url_queue")

    # Create threads
    commons.DomainQueueManager(args, domain_queue, url_queue)
    commons.UrlQueueManager(args, url_queue, uagent)

    # Get domains
    domains = commons.get_domains(uagent, args)

    print(colored("Scoring and checking the domains...\n", "yellow", attrs=["bold"]))
    for domain in domains:
        domain_queue.put(domain)

    domain_queue.join()
    url_queue.join()
    return

if __name__ == "__main__":
    main()
