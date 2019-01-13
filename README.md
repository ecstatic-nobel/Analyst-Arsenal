# [Analyst Arsenal (A²)™]  
##### Be the first to know on a need-to-know basis.  

### Description  
With `aa_adhoc`, run through a list of URLs and recursively check sites for malicious files based on predefined file extensions.  

With `aa_certstream`, find out when a phishing kit has been staged on a domain. With this information, you can be amongst the first to:  
- Know  
- Block  
- Report  
- Analyze  

With `aa_urlscan`, easily search [urlscan.io](https://urlscan.io/) and recursively check sites for malicious files based on predefined file extensions.  

With `aa_whoisds`, download a list of newly registered domains from [WHOIS Domain Search](https://whoisds.com/newly-registered-domains), score the domains, and search for signs of phishing activity.  

### Prerequisites  
- Ubuntu 18.04+ (should work on other Linux distros)  
- Python 2.7.14  
- Git  
- Torsocks (optional: used with flag `--tor`)  

### Setup  
1. Open a terminal and run the following command:  
    ```bash  
    git clone https://github.com/ecstatic-nobel/analyst_arsenal.git  
    cd analyst_arsenal  
    bash py_pkg_update.sh  
    ```  

### Usage  
**aa_adhoc**  
The following command will:  
- Make requests to the domains retrieved from a file  
- Recursively download the site when an open directory hosting a file with the desired file extension  

3 positional arguments needed:  
- **Input File**     : Path to the file containing URLs  
- **File Extension** : 7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip  

Optional arguments:  
- **--file-dir** : Directory to use for interesting files detected (default: ./InterestingFiles/)  
- **--kit-dir**  : Directory to use for phishing kits detected (default: ./KitJackinSeason/)  
- **--level**    : Recursion depth (default=1, infinite=0)  
- **--quiet**    : Don't show wget output  
- **--threads**  : Numbers of threads to spawn  
- **--timeout**  : Set time to wait for a connection  
- **--tor**      : Download files via the Tor network  
- **--verbose**  : Show error messages  

```bash  
python aa_adhoc.py <INPUT_FILE> <FILE_EXTENSION> [--file-dir] [--kit-dir] [--level] [--quiet] [--threads] [--timeout] [--tor] [--verbose]  
```  

**aa_certstream**  
The following command will:  
- Stream CT logs via Certstream  
- Score and add suspicious domains to a queue while other domains continue to be scored  
- Simultaneously make requests to the domains in the queue to search for predefined file extensions  
- Recursively download the site when an open directory is found hosting a file with a particular extension  

Optional arguments:  
- **--file-dir**     : Directory to use for interesting files detected (default: ./InterestingFiles/)  
- **--kit-dir**      : Directory to use for phishing kits detected (default: ./KitJackinSeason/)  
- **--level**        : Recursion depth (default=1, infinite=0)  
- **--log-nc**       : File to store domains that have not been checked  
- **--quiet**        : Don't show wget output  
- **--score**        : Minimum score to trigger a session (Default: 75)  
- **--threads**      : Numbers of threads to spawn  
- **--timeout**      : Set time to wait for a connection  
- **--tor**          : Download files via the Tor network  
- **--verbose**      : Show domains being scored  
- **--very-verbose** : Show error messages  

```bash  
python aa_certstream.py [--file-dir] [--kit-dir] [--level] [--log-nc] [--quiet] [--score] [--threads] [--timeout] [--tor] [--verbose] [--very-verbose]  
```  

**aa_urlscan**  
The following command will:  
- Make requests to the domains retrieved from urlscan.io  
- Recursively download the site when an open directory hosting a file with the desired file extension  

3 positional arguments needed:  
- **Query Type**     : automatic, manual, certstream, openphish, phishtank, twitter, urlhaus  
- **Delta**          : Number of days back to search (GMT)  
- **File Extension** : 7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip  

Optional arguments:  
- **--file-dir** : Directory to use for interesting files detected (default: ./InterestingFiles/)  
- **--kit-dir**  : Directory to use for phishing kits detected (default: ./KitJackinSeason/)  
- **--level**    : Recursion depth (default=1, infinite=0)  
- **--quiet**    : Don't show wget output  
- **--threads**  : Numbers of threads to spawn  
- **--timeout**  : Set time to wait for a connection  
- **--tor**      : Download files via the Tor network  
- **--verbose**  : Show error messages  

```bash  
python aa_urlscan.py <QUERY_TYPE> <DELTA> <FILE_EXTENSION> [--file-dir] [--kit-dir] [--level] [--quiet] [--threads] [--timeout] [--tor] [--verbose]  
```  
**Note**: If the path is a file, it will be automatically downloaded.  

**aa_whoisds**  
- Download a list of newly registered domains from WHOIS Domain Search (whoisds.com)  
- Score and add suspicious domains to a queue while other domains continue to be scored  
- Simultaneously make requests to the domains in the queue to search for predefined file extensions  
- Recursively download the site when an open directory is found hosting a file with a particular extension  

1 positional argument needed:  
- **Delta** : Number of days back to search (GMT)  

Optional arguments:  
- **--file-dir**     : Directory to use for interesting files detected (default: ./InterestingFiles/)  
- **--kit-dir**      : Directory to use for phishing kits detected (default: ./KitJackinSeason/)  
- **--level**        : Recursion depth (default=1, infinite=0)  
- **--log-nc**       : File to store domains that have not been checked  
- **--quiet**        : Don't show wget output  
- **--score**        : Minimum score to trigger a session (Default: 75)  
- **--threads**      : Numbers of threads to spawn  
- **--timeout**      : Set time to wait for a connection  
- **--tor**          : Download files via the Tor network  
- **--verbose**      : Show domains being scored  
- **--very-verbose** : Show error messages  

```bash  
python aa_whoisds.py <DELTA> [--file-dir] [--kit-dir] [--level] [--log-nc] [--quiet] [--score] [--threads] [--timeout] [--tor] [--verbose] [--very-verbose]  
```  

### Things to know  
- Be responsible!!!  
- Downloads via Tor happen over **127.0.0.1:9050**  
- These scripts **will not** check Torsocks settings  

Please fork, create merge requests, and help make this better.  
