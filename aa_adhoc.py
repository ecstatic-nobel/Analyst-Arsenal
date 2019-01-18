#!/usr/bin/python
"""
Description:
- Make requests to the domains retrieved from a file
- Recursively download the site when an open directory hosting a file with the desired file extension

1 positional arguments needed:
- Input File : Path to the file containing URLs

Optional arguments:
- --directory    : Save data to CAP_DIR (default: ./Captures/)
- --level        : Recursion depth (default=1, infinite=0)
- --quiet        : Don't show wget output
- --threads      : Numbers of threads to spawn
- --timeout      : Set the connection timeout to TIMEOUT
- --tor          : Download files via the Tor network
- --very-verbose : Show error messages

Usage:
```
python aa_adhoc.py <INPUT_FILE> [--directory] [--level] [--quiet] [--threads] [--timeout] [--tor] [--very-verbose]
```

Debugger: open("/tmp/aa.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import argparse

import commons


# Parse Arguments
parser = argparse.ArgumentParser(description="Attempt to detect phishing kits and open directories on urlscan.io.")
parser.add_argument(metavar="input file",
                    dest="input_file",
                    help="Path to the file containing URLs")
parser.add_argument("--directory",
                    dest="cap_dir",
                    default="./Captures/",
                    required=False,
                    help="Download data to CAP_DIR (default: ./Captures)")
parser.add_argument("--level",
                    dest="level",
                    default=1,
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
                    help="Set the connection timeout to TIMEOUT")
parser.add_argument("--tor",
                    dest="tor",
                    action="store_true",
                    required=False,
                    help="Download files over the Tor network")
parser.add_argument("--very-verbose",
                    dest="very_verbose",
                    action="store_true",
                    required=False,
                    help="Show error messages")
# Fix directory names
args = commons.fix_directory(parser.parse_args())

def main():
    """ """
    # Check if output directories exist
    commons.check_path(args)

    # Print start messages
    commons.show_summary(args)
    commons.show_networking(args) # globals: proxies, torsocks

    # Read config.yaml
    commons.read_config(args) # globals: config

    # Recompile exclusions
    commons.recompile_exclusions() # globals: exclusions

    # Create queues
    url_queue = commons.create_queue("url_queue")

    # Create threads
    commons.UrlQueueManager(args, url_queue)

    # Read file containing URLs
    urls = commons.read_file(args.input_file)

    # Process URLs
    for url in urls:
        url_queue.put(url)

    url_queue.join()
    return

if __name__ == "__main__":
    main()
