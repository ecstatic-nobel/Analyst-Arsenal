#!/usr/bin/python
"""
Description:
- Make requests to the domains retrieved from urlscan.io
- Recursively download the site when an open directory hosting a file with the desired file extension

3 positional arguments needed:
- Query Type : automatic, manual, certstream, openphish, phishtank, twitter, urlhaus
- Delta : Number of days back to search (GMT)
- File Extension : 7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip

Optional arguments:
- --file-dir : Directory to use for interesting files detected (default: ./InterestingFiles/)
- --kit-dir  : Directory to use for phishing kits detected (default: ./KitJackinSeason/)
- --level    : Recursion depth (default=1, infinite=0)
- --quiet    : Don't show wget output
- --threads  : Numbers of threads to spawn
- --timeout  : Set time to wait for a connection
- --tor      : Download files via the Tor network
- --verbose  : Show error messages

Usage:

```
python opendir_urlscan.py <QUERY_TYPE> <DELTA> <FILE_EXTENSION> [--exclude=CSV] [--file-dir] [--kit-dir] [--quiet] [--timeout] [--tor] [--verbose]
```

Debugger: open("/tmp/opendir.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse
import os
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)

import commons


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories on urlscan.io.")
parser.add_argument(metavar="query type",
                    dest="query_type",
                    choices=["automatic", "manual", "certstream", "openphish", "phishtank", "twitter", "urlhaus"],
                    help="automatic, manual, certstream, openphish, phishtank, twitter, urlhaus")
parser.add_argument(dest="delta",
                    type=int,
                    help="Number of days back to search (GMT)")
parser.add_argument(metavar="file extension",
                    dest="ext",
                    choices=["7z", "apk", "bat", "bz", "bz2", "crypt", "dll", "doc", "docx", "exe", "gz", "hta", "iso", "jar", "json", "lnk", "ppt", "ps1", "py", "rar", "sfx", "sh", "tar", "vb", "vbs", "xld", "xls", "xlsx", "zip"],
                    help="7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip")
parser.add_argument("--file-dir",
                    dest="file_dir",
                    default="./InterestingFile/",
                    required=False,
                    help="Directory to use for interesting files detected (default: ./InterestingFiles))")
parser.add_argument("--kit-dir",
                    dest="kit_dir",
                    default="./KitJackinSeason/",
                    required=False,
                    help="Directory to use for phishing kits detected (default: ./KitJackinSeason))")
parser.add_argument("--level",
                    dest="level",
                    default=0,
                    required=False,
                    type=str,
                    help="Directory depth (default=1, infinite=0")
parser.add_argument("--quiet",
                    dest="quiet",
                    action="store_true",
                    required=False,
                    help="Don't show wget output")
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
                    help="Show error messages")
args   = parser.parse_args()
uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"

def main():
    """ """
    # Check if output directories exist
    commons.check_path(args)

    # Print start messages
    commons.show_summary(args)
    commons.show_networking(args, uagent)

    # Read suspicious.yaml and external.yaml
    suspicious = commons.read_externals()

    # Recompile exclusions
    commons.recompile_exclusions()

    # Build dict of extensions
    extensions = {}
    extensions.update(suspicious["archives"])
    extensions.update(suspicious["files"])

    # Request URLs from urlscan.io
    urls = commons.query_urlscan(args, suspicious["queries"], uagent, extensions)

    # Create queues
    recursion_queue = commons.create_queue("recursion_queue")

    # Create threads
    commons.RecursiveQueueManager(args, recursion_queue, uagent, extensions)

    # Process URLs
    for url in urls:
        recursion_queue.put(url)

    recursion_queue.join()
    return

if __name__ == "__main__":
    main()
