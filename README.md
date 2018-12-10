# [Analyst Arsenal (A²)™]
##### A tool belt for analysts to continue fighting the good fight.  

#### Description  
##### opendir_certstream
After catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream, make a request to the site to check for predefined file extensions in open directories.  

##### opendir_certstream
Search for specific filetypes submitted to [urlscan.io](https://urlscan.io/) and recursively download the webpage if predefined file extensions are found.  

#### Prerequisites  
- Python 2.7.14  

#### Setup  
1. Open a terminal and run the following command:  
```bash
git clone https://github.com/leunammejii/analyst_arsenal.git
mv analyst_arsenal-master analyst_arsenal
cd analyst_arsenal
bash py_pkg_update.sh
```

### Usage
**opendir_certstream**  
The following command will:  
- Stream CT logs via Certstream  
- Score and add suspicious domains to a queue while other domains continue to be scored  
- Simultaneously make requests to the domains in the queue to search for predefined file extensions  
- Recursively download the site when an open directory is found hosting a file with a particular extension  
```bash
python opendir_certstream.py
```
**Note**: Any URLs in the queue will be lost once the program stops.  

**Download**
![opendir_certstream - Download](https://github.com/leunammejii/analyst_arsenal/blob/master/static/assets/opendir_certstream_download.png)  

**opendir_urlscan**   
The following command will:  
- Make requests to the domains retrieved from urlscan.io  
- Recursively download the site when an open directory hosting a file with the desired file extension  

3 positional arguments needed:  
- **Query Type**     : automatic, manual, certstream, openphish, phishtank, twitter, urlhaus  
- **Delta**          : Number of days back to search (GMT)  
- **File Extension** : 7z, apk, bat, bz, bz2, crypt, dll, doc, docx, exe, gz, hta, iso, jar, json, lnk, ppt, ps1, py, rar, sfx, sh, tar, vb, vbs, xld, xls, xlsx, zip   

Optional arguments:  
- **Dry Run** : Perform a test run to see what would be downloaded  
- **Exclude** : A comma-separated list of domains to not download content from (ex. 'google.com,bing.com')  
```bash
python opendir_urlscan.py <QUERY_TYPE> <DELTA> <FILE_EXTENSION> [--dry-run] [--exclude=CSV]
```
**Note**: If the path is a file, it will be downloaded regardless of whether it's an open directory.  

**Help**
![opendir_urlscan - Help](https://github.com/leunammejii/analyst_arsenal/blob/master/static/assets/opendir_urlscan_help.png)  

**Dry Run**
![opendir_urlscan - Dry Run](https://github.com/leunammejii/analyst_arsenal/blob/master/static/assets/opendir_urlscan_dryrun.png)  

**Download**
![opendir_urlscan - Download](https://github.com/leunammejii/analyst_arsenal/blob/master/static/assets/opendir_urlscan_download.png)  

#### Things to know  
- Be responsible.  

Please fork, create merge requests, and help make this better.  
