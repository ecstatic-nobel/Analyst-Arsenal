#!/usr/bin/python
#
# Usage: bash dnstwist.sh PATH_TO_DNSTWIST_SCRIPT
#

DNSTWIST_SCRIPT="$1"

if [[ -f "$DNSTWIST_SCRIPT" ]]
then
    KEYWORDS=$(
        grep -A 1000 -E ^keywords config.yaml | \
            grep -B 1000 -E ^queries | \
            grep -E "^\s+" | \
            tr -d ' ' | \
            grep -v \# | \
            grep -vE "^\.|^\-"
    )

    echo "keywords:" > dns_twisted.yaml
    echo "$KEYWORDS" | while read -r KEYWORD
    do
        SCORE=$(echo "$KEYWORD" | sed "s/.*://gi")
        KEYWORD=$(echo "$KEYWORD" | grep -oE "'.+'" | tr -d "'")
        TWISTED=$(python "$DNSTWIST_SCRIPT" --format idle -t 10 "$KEYWORD".com)
        echo "$TWISTED" | \
            grep -vE "^xn--|$KEYWORD" | \
            sed "s/^/    '/gi" | \
            sed "s/$/': $SCORE/gi" >> dns_twisted.yaml
    done

    sed -i "s/\.com':/':/gi" dns_twisted.yaml
else
    file "$DNSTWIST_SCRIPT"
fi
