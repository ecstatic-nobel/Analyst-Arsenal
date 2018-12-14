#!/usr/bin/bash
#
# Description: Attempt to generate a report on what's found.
# Usage      : bash report.sh DIRECTORY
#

for x in $(ls "$1" | grep -vE ".placeholder|^\.$|^\.\.$")
do
    (
        echo -e "\n########################################################\n"

        echo "$x"

        cd ./*/"$x"

        find -name *.zip -exec unzip -o {} \;
        find -name *.rar -exec unrar e {} \;

        touch .inv

        echo -e "DateFound" > pkt.report
        date +%m/%d/%Y >> pkt.report

        echo -e "\nReferenceLink" >> pkt.report
        echo - >> pkt.report

        echo -e "\nEmailType" >> pkt.report
        grep -rhoE "\s+=\s+('|\")\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b('|\")" | \
            tr -d " =" | \
            grep \@ | \
            awk -F "@" '{print $2}' | \
            awk -F "." '{print $1}' | \
            grep -v example | \
            sort -u >> pkt.report

        echo -e "\nKitMailer" >> pkt.report
        echo - >> pkt.report

        echo -e "\nTarget" >> pkt.report
        echo - >> pkt.report

        echo -e "\nPhishingDomain" >> pkt.report
        echo "$x" | \
            sed "s/^\./hxxps:\/\//gi" >> pkt.report

        echo -e "\nKitName" >> pkt.report
        find . -name *.zip -exec md5sum {} \; | \
            awk -F "  " '{print $2}' | \
            awk -F "/" '{print $2}' | \
            sort -u >> pkt.report

        echo -e "\nThreatActor" >> pkt.report
        echo - >> pkt.report

        echo -e "\nKitHash" >> pkt.report
        find -name *.zip -exec md5sum {} \; | \
            awk -F "  " '{print $1}' | \
            sort -u >> pkt.report

        echo -e "\nThreatActorEmail" >> pkt.report
        grep -rhoE "\s+=\s+('|\")\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b('|\")" | \
            tr -d " ='\"" | \
            grep \@ | \
            grep -v example.com | \
            sort -u >> pkt.report

        mv ../"${PWD##*/}" ../."${PWD##*/}"
    )
done
