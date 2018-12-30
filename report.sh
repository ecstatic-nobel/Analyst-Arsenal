#!/usr/bin/bash
#
# Description: Attempt to generate a report on ZIP files found.
# Usage      : bash report.sh PATH_TO_KitJackinSeason
#


echo "DateFound,ReferenceLink,ThreatActorEmail,EmailType,KitMailer,Target,PhishingDomain,KitName,ThreatActor,KitHash,KitUrl"

find "$1" -name "*.zip" | sort | while read x
do
    (
        cd $(dirname "$x")

        touch .inv

        # find -name *.rar -exec unrar e {} \; > /dev/null
        find -maxdepth 1 -name *.zip -exec unzip -qo {} \;
        find -name index.html?* -exec rm {} \;

        echo -e "\n########################################################\n" > pkt.report

        echo -e "DateFound" >> pkt.report
        DateFound=$(echo "$x" | grep -oE "[0-9]{4}(\-[0-9]{2}){2}")
        echo "$DateFound" >> pkt.report

        echo -e "\nReferenceLink" >> pkt.report
        ReferenceLink="-"
        echo "$ReferenceLink" >> pkt.report

        echo -e "\nThreatActorEmail" >> pkt.report
        ThreatActorEmail=$(
            grep -rhoE "\s+=\s+('|\")\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b('|\")" | \
                tr -d " ='\"" | \
                grep \@ | \
                grep -v example.com | \
                sort -u | \
                paste -sd "|" -
        )
        
        if [[ "$ThreatActorEmail" == "" ]]
        then
            ThreatActorEmail="-"
            echo "-" >> pkt.report
        else
            echo "$ThreatActorEmail" >> pkt.report
        fi            

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
        
        if [[ "$EmailType" == "" ]]
        then
            EmailType="-"
            echo "-" >> pkt.report
        else
            echo "$EmailType" >> pkt.report
        fi
        

        echo -e "\nKitMailer" >> pkt.report
        KitMailer="-"
        echo "$KitMailer" >> pkt.report

        echo -e "\nTarget" >> pkt.report
        Target="-"
        echo "$Target" >> pkt.report

        echo -e "\nPhishingDomain" >> pkt.report
        PhishingDomain=$(dirname "$x" | rev | awk -F "/" '{print $1}' | rev)
        echo "$PhishingDomain" >> pkt.report

        echo -e "\nKitName" >> pkt.report
        KitName=$(
            find . -name *.zip -exec md5sum {} \; | \
                awk -F "  " '{print $2}' | \
                awk -F "/" '{print $2}' | \
                sort -u | \
                paste -sd "|" -
        )
        
        if [[ "$KitName" == "" ]]
        then
            KitName="-"
            echo "-" >> pkt.report
        else
            echo "$KitName" >> pkt.report
        fi

        echo -e "\nThreatActor" >> pkt.report
        ThreatActor=$(
            grep -rhioE "(created by .+|hacked by .+|coded by .+|edited by .+|signed by .+|made by .+)([^\r|\n|\=|\+|\"|\'|\,]+)\s+([\,\=\+\"\']|\-\-)" | \
                sort -u | \
                paste -sd "|" -
        )
        
        if [[ "$ThreatActor" == "" ]]
        then
            ThreatActor="-"
            echo "-" >> pkt.report
        else
            echo "$ThreatActor" >> pkt.report
        fi

        echo -e "\nKitHash" >> pkt.report
        KitHash=$(
            find -name *.zip -exec md5sum {} \; | \
                awk -F "  " '{print $1}' | \
                sort -u | \
                paste -sd "|" -
        )
        
        if [[ "$KitHash" == "" ]]
        then
            KitHash="-"
            echo "-" >> pkt.report
        else
            echo "$KitHash" >> pkt.report
        fi

        echo -e "\nKitUrl" >> pkt.report
        KitUrl=$(echo "$x" | sed -e "s/.*KitJackinSeason\//hxxps:\/\//gi")
        echo "hxxps://$KitUrl" >> pkt.report

        echo "$DateFound,$ReferenceLink,$ThreatActorEmail,$EmailType,$KitMailer,$Target,$PhishingDomain,$KitName,$ThreatActor,$KitHash,$KitUrl"

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

# find -name *.rar -exec md5sum {} \; | sort > "$1/md5sum.report"
find -name *.zip -exec md5sum {} \; | sort >> "$1/md5sum.report"
