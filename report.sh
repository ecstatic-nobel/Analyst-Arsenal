#!/usr/bin/bash
#
# Description: Attempt to generate a report on what's found.
# Usage      : bash report.sh DIRECTORY
#


echo "DateFound,ReferenceLink,ThreatActorEmail,EmailType,KitMailer,Target,PhishingDomain,KitName,ThreatActor,KitHash,KitUrl"

for x in $(ls "$@" | grep -vE ".placeholder|^\.$|^\.\.$|md5sum\.report")
do
    (
        cd "$1/$x"

        find -name *.rar -exec unrar e {} \; > /dev/null
        find -name *.zip -exec unzip -qo {} \;

        touch .inv

        echo -e "\n########################################################\n" > pkt.report

        echo -e "DateFound" >> pkt.report
        DateFound=$(date +%m/%d/%Y)
        echo "$DateFound" >> pkt.report

        echo -e "\nReferenceLink" >> pkt.report
        ReferenceLink="-"
        echo "$ReferenceLink" >> pkt.report

        echo -e "\nThreatActorEmail" >> pkt.report
        ThreatActorEmail=$(
            grep -rhoE "\s+=\s+('|\")\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b('|\")" KitJackinSeason/.secureapple-appleid.servehttp.com | \
                tr -d " ='\"" | \
                grep \@ | \
                grep -v example.com | \
                sort -u | \
                paste -sd "|" -
        )
        echo "$ThreatActorEmail" >> pkt.report
            

        echo -e "\nEmailType" >> pkt.report
        EmailType=$(
            grep -rhoE "\s+=\s+('|\")\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b('|\")" | \
                tr -d " =" | \
                grep \@ | \
                awk -F "@" '{print $2}' | \
                awk -F "." '{print $1}' | \
                grep -v example | \
                sort -u | \
                paste -sd "|" -
        )
        echo $EmailType >> pkt.report
        

        echo -e "\nKitMailer" >> pkt.report
        KitMailer="-"
        echo "$KitMailer" >> pkt.report

        echo -e "\nTarget" >> pkt.report
        Target="-"
        echo "$Target" >> pkt.report

        echo -e "\nPhishingDomain" >> pkt.report
        PhishingDomain="$x"
        echo "$PhishingDomain" >> pkt.report

        echo -e "\nKitName" >> pkt.report
        KitName=$(
            find . -name *.zip -exec md5sum {} \; | \
                awk -F "  " '{print $2}' | \
                awk -F "/" '{print $2}' | \
                sort -u | \
                paste -sd "|" -
        )
        echo $KitName >> pkt.report

        echo -e "\nThreatActor" >> pkt.report
        ThreatActor=$(
            grep -rhioE "(created by .+|hacked by .+|coded by .+|edited by .+|signed by .+|made by .+)([^\r|\n|\=|\+|\"|\'|\,]+)\s+([\,\=\+\"\']|\-\-)" | \
                sort -u | \
                paste -sd "|" -
        )
        echo "$ThreatActor" >> pkt.report

        echo -e "\nKitHash" >> pkt.report
        KitHash=$(
            find -name *.zip -exec md5sum {} \; | \
                awk -F "  " '{print $1}' | \
                sort -u | \
                paste -sd "|" -
        )
        echo "$KitHash" >> pkt.report

        echo -e "\nKitUrl" >> pkt.report
        KitUrl="hxxps://$x/$(ls *.zip)"
        echo "$KitUrl" >> pkt.report

        echo "$DateFound,$ReferenceLink,$ThreatActorEmail,$EmailType,$KitMailer,$Target,$PhishingDomain,$KitName,$ThreatActor,$KitHash,$KitUrl"

        mv ../"${PWD##*/}" ../."${PWD##*/}"

        # ABUSE_EMAIL_RECIPIENT=$(
        #     echo "$x" | \
        #         rev | \
        #         cut -d . -f 1-2 | \
        #         rev | \
        #         xargs whois | \
        #         grep -i abuse | \
        #         grep -i email | \
        #         tail -n 1 | \
        #         awk -F ": " '{print $2}'
        # )
    )
done

find -name *.rar -exec md5sum {} \; | sort > "$1/md5sum.report"
find -name *.zip -exec md5sum {} \; | sort >> "$1/md5sum.report"
