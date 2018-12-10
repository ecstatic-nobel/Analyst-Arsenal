#!/opt/splunk/bin/python

import argparse
from collections import OrderedDict
from datetime import datetime
from datetime import timedelta
import glob
import os
import subprocess
import sys

script_path = os.path.dirname(os.path.realpath(__file__)) + "/_tp_modules"
sys.path.insert(0, script_path)
import requests
from termcolor import colored, cprint
import tqdm


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
                    dest="file_extension",
                    help="7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip")
parser.add_argument("--dryrun",
                    dest="dry_run",
                    action="store_true",
                    required=False,
                    help="Perform a test run to see what would be downloaded")
parser.add_argument("--exclude",
                    dest="exclude",
                    required=False,
                    help="A comma-separated list of domains to not download content from (ex. 'google.com,bing.com')")
args = parser.parse_args()

# Print dry-run message if True
if args.dry_run:
    print(colored("Starting dry run...\n", "yellow", attrs=["bold"]))

# Print summary of what's about to be checked
print("Summary:")
print("    query_type     : {}".format(args.query_type))
print("    delta          : {}".format(args.delta))
print("    file_extension : {}".format(args.file_extension))

if args.exclude:
    exclusions = args.exclude.split(',')
    print("    exclusions     : {}".format(exclusions))

print("")

queries = {
    "automatic"  : "task.method%3Aautomatic",
    "manual"     : "task.method%3Amanual",
    "certstream" : "(task.source%3Acertstream-idn OR \
                    task.source%3Acertstream-suspicious)",
    "openphish"  : "task.source%3Aopenphish",
    "phishtank"  : "task.source%3Aphishtank",
    "twitter"    : "(task.source%3Atwitter OR \
                    task.source%3Atwitter_illegalFawn OR \
                    task.source%3Atwitter_phishingalert)",
    "urlhaus"    : "task.source%3Aurlhaus"
}

archives = {
    "7z"   : "application/x-7z-compressed",
    "gz"   : "application/x-gzip",
    "rar"  : "application/x-rar",
    "tar"  : "donotcheck",
    "zip"  : "application/zip"
}

files = {
    "apk"  : "application/java-archive",
    "bat"  : "donotcheck",
    "dll"  : "application/x-dosexec",
    "doc"  : "application/msword",
    "docx" : "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "exe"  : "application/x-dosexec",
    "hta"  : "donotcheck",
    "html" : "donotcheck",
    "iso"  : "application/octet-stream",
    "jar"  : "application/java-archive",
    "json" : "donotcheck",
    "lnk"  : "application/octet-stream",
    "ppt"  : "application/vnd.ms-powerpoint",
    "ps1"  : "donotcheck",
    "py"   : "donotcheck",
    "sh"   : "donotcheck",
    "vb"   : "donotcheck",
    "vbs"  : "donotcheck",
    "xls"  : "application/vnd.ms-excel",
    "xlsx" : "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
}

extensions = {}
extensions.update(archives)
extensions.update(files)

def main():
    """ """
    qtype = args.query_type.lower()
    delta = args.delta
    ext   = args.file_extension.lower()

    today    = datetime.now()
    timespan = datetime.strftime(today - timedelta(delta), "%a, %d %b %Y 05:00:00")
    timespan = datetime.strptime(timespan, "%a, %d %b %Y %H:%M:%S")
    
    # Request data from urlscan.io
    api    = "https://urlscan.io/api/v1/search/?q={}%20AND%20filename%3A.{}&size=10000"
    uagent = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"
    resp   = requests.get(api.format(queries[qtype], ext),
                          headers={"User-Agent": uagent},
                          timeout=10)

    if not (resp.status_code == 200 and "results" in resp.json().keys()):
        exit(0)


    results = resp.json()["results"]
    urls    = []

    for result in results:
        # Break at time specified
        analysis_time = datetime.strptime(result["task"]["time"], "%Y-%m-%dT%H:%M:%S.%fZ")

        if analysis_time < timespan:
            break

        # Build list of URLs ending with specified extension or Mime-Type
        url = result["page"]["url"]

        if url.endswith('.{}'.format(ext)):
            urls.append(url)
            continue
    
        if "files" in result.keys():
            files = [x for x in result["files"] if x["mimeType"].startswith(extensions[ext])]

            if len(files) > 0:
                urls.append(url)

    for url in urls:
        # Check if the current URL has already been redirected to
        if "redirect" in vars() and redirect == url:
            del redirect
            continue

        # Split URL into parts
        split_url = url.split("/")
        protocol  = split_url[0]
        domain    = split_url[2]
        
        # Skip exclusions
        if args.exclude and domain in exclusions:
            continue

        tqdm.tqdm.write(
            "[*] Original : "
            "{}".format("{}".format(colored(url, "cyan")))
        )
        url = "//".join([protocol, domain])

        # Build list of URL resources
        resources = split_url[3:]
        resources = ['/{}'.format(x) for x in resources]
        resources.insert(0, "")

        for resource in resources:
            # Combine current URL and resource
            url = "{}{}".format(url, resource)

            # Follow URL path and continue if a download was detected for a dry-run
            if "dry_domain" in vars():
                tqdm.tqdm.write(
                    "[*] Download : "
                    "{}".format("{} (Recursively downloaded)".format(colored(url, "green", attrs=["underline", "bold"]))))
                continue

            # Send first request to the URL
            tqdm.tqdm.write(
                "[*] Session  : "
                "{}".format("{}".format(colored(url, "blue"))))

            try:
                resp = requests.get(url, headers={"User-Agent": uagent}, timeout=5, allow_redirects=True)
            except:
                continue

            if resp.status_code != 200:
                continue

            # An open directory is found
            if "Index of " in resp.content:
                if glob.glob("./*/{}".format(domain.split(":")[0])):
                    tqdm.tqdm.write(
                        "[-] Skipping : "
                        "{}".format("{} (Directory '{}' already exists)".format(colored(url, "red", attrs=["underline", "bold"]), domain.split(":")[0])))
                    break

                for extension in extensions.keys():
                    if "{}<".format(extension) in resp.content.lower() and extension in archives:
                        directory = "KitJackinSeason"
                    elif "{}<".format(ext) in resp.content.lower() and extension in files:
                        directory = "InterestingFile"
                    else:
                        continue

                    tqdm.tqdm.write(
                        "[*] Download : "
                        "{}".format("{} ('Index of ' found)".format(colored(url, "green", attrs=["underline", "bold"]))))

                    if args.dry_run:
                        dry_domain = True
                        break
            
                    try:
                        if directory == "InterestingFile":
                            os.mkdir("./InterestingFile/{}".format(domain.split(":")[0]))
                        subprocess.call([
                            "wget",
                            "--execute=robots=off",
                            "--tries=2",
                            "--no-clobber",
                            "--timeout=5",
                            "--waitretry=0",
                            "--directory-prefix=./{}/{}".format(directory, domain.split(":")[0]),
                            "--content-disposition",
                            "--recursive",
                            "--level=0",
                            "--no-parent",
                            url
                        ])
                        break
                    except:
                        continue

            # A URL is found ending in the specified extension but the server responded with no Content-Type
            if "Content-Type" not in resp.headers.keys():
                if os.path.exists("./InterestingFile/{}".format(domain.split(":")[0])):
                    tqdm.tqdm.write(
                        "[-] Skipping : "
                        "{}".format("{} (Directory '{}' already exists)".format(colored(url, "red", attrs=["underline", "bold"]), domain.split(":")[0])))
                    break

                if url.endswith('.{}'.format(ext)):
                    if resp.url != url:
                        redirect = resp.url
                        tqdm.tqdm.write(
                            "[*] Redirect : "
                            "{}".format("{} (Responded with no Content-Type)".format(colored(redirect, "green", attrs=["underline", "bold"]))))
                    else:
                        tqdm.tqdm.write(
                            "[*] Download : "
                            "{}".format("{} (Responded with no Content-Type)".format(colored(url, "green", attrs=["underline", "bold"]))))

                    if args.dry_run:
                        continue

                    try:
                        os.mkdir("./InterestingFile/{}".format(domain.split(":")[0]))
                        subprocess.call([
                            "wget",
                            "--execute=robots=off",
                            "--tries=2",
                            "--no-clobber",
                            "--timeout=5",
                            "--waitretry=0",
                            "--directory-prefix=./InterestingFile/{}".format(domain.split(":")[0]),
                            "--content-disposition",
                            "--no-parent",
                            url
                        ])
                        continue
                    except:
                        continue

            # A file is found with the Mime-Type of the specified extension
            if resp.headers["Content-Type"].startswith(extensions[ext]) or url.endswith(".{}".format(ext)):
                if os.path.exists("./InterestingFile/{}".format(domain.split(":")[0])):
                    tqdm.tqdm.write(
                        "[-] Skipping : "
                        "{}".format("{} (Directory '{}' already exists)".format(colored(url, "red", attrs=["underline", "bold"]), domain.split(":")[0])))
                    break

                if resp.url != url:
                    redirect = resp.url
                    tqdm.tqdm.write(
                        "[*] Redirect : "
                        "{}".format("{} ({} found)".format(colored(redirect, "green", attrs=["underline", "bold"]), ext)))
                else:
                    tqdm.tqdm.write(
                        "[*] Download : "
                        "{}".format("{} ({} found)".format(colored(url, "green", attrs=["underline", "bold"]), ext)))

                if args.dry_run:
                    continue

                try:
                    os.mkdir("./InterestingFile/{}".format(domain.split(":")[0]))
                    subprocess.call([
                        "wget",
                        "--execute=robots=off",
                        "--tries=2",
                        "--no-clobber",
                        "--timeout=5",
                        "--waitretry=0",
                        "--directory-prefix=./InterestingFile/{}".format(domain.split(":")[0]),
                        "--content-disposition",
                        "--no-parent",
                        url
                    ])
                    continue
                except:
                    continue

        if "dry_domain" in vars():
            del dry_domain
    return

if __name__ == "__main__":
    main()