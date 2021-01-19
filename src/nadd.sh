#!/bin/bash
## This script helps to block IP addresses or networks that can be identified as DDoS.
##
## https://github.com/pipisco/nadd
## With love, pipisco (c) 2021
##
## ----------------------------------------------------------
## Port
PORT=443
## Entry threshold
ENTRY_THRESHOLD=1000
## If the parameter is correct, then the blocking will pass through the networks
NETWORK_MODE="false"
## TLS rule
## By default is 900 seconds (15 minutes)
TLS=900
## Rule DB
WORK_DIR="/var/lib/nadd"

## Add rule
## ----------------------------------------------------------
## @param string $ip
## @return void
function saveRuleTimestamp()
{
    unixtimestamp=`date +"%s"`
    let "tlsRule = ${unixtimestamp} + ${TLS}"
    if [ ! -d ${WORK_DIR} ]; then
        mkdir -p ${WORK_DIR}
    fi
    if [ ! -f ${WORK_DIR}/${1}.db ]; then
        touch ${WORK_DIR}/${1}.db
        echo ${tlsRule} > ${WORK_DIR}/${1}.db
        iptables -A INPUT -s ${1} -j DROP
    fi
}

## Dropped rule if expire
## ----------------------------------------------------------
## @param string ${ip}
## @return $void
function dropRule()
{
    for i in `ls ${WORK_DIR}/*.db`; do
        unixtimestamp=`date +"%s"`
        tlsRule=`cat ${i}`
        if [ "${unixtimestamp}" -gt "${tlsRule}" ]; then
           ip="$(basename -- ${i})"
           ip=`echo ${ip} | sed 's/.db//g'`
           iptables -D INPUT -s ${ip} -j DROP > /dev/null
           rm -rf ${i}
        fi
    done
}

## Return a list of type addresses whose occurrence
## is greater than the specified threshold
## ----------------------------------------------------------
## @param int $port
## @return string $networks
function getIpListByRate()
{
    networks=""
    netstat -ntu | grep ":${1} " | awk '{print $5}' | cut -d: -f1 -s | sort | uniq -c | sort -nk1 -r | \
    while read i; do
        count=`echo ${i} | awk {'print $1'}`
        ip=`echo ${i} | awk {'print $2'}`
        if [ "${ENTRY_THRESHOLD}" -ge "${count}" ]; then
            echo $networks
            break
        fi
        networks+=" ${ip}"
    done
}

## Return a list of type networks whose occurrence
## is greater than the specified threshold
## @NOTE: Use this feature only for high attacks
## ----------------------------------------------------------
## @param int $port
## @return string $networks
function getNetworksListByRate()
{
    networks=""
    netstat -ntu | grep ":${1} " | awk '{print $5}' | cut -d: -f1 -s | cut -f1,2 -d'.' | sed 's/$/.0.0/' | sort | uniq -c | sort -nk1 -r | \
    while read i; do
        count=`echo ${i} | awk {'print $1'}`
        ip=`echo ${i} | awk {'print $2'}`
        if [ "${ENTRY_THRESHOLD}" -ge "${count}" ]; then
            echo $networks
            break
        fi
        networks+=" ${ip}"
    done
}

## Help
## ----------------------------------------------------------
## @return exit
function help()
{
    echo "Usage: nadd [-1246AaCfGgKkMNnqsTtVvXxYy] [-p port] [-t entry_threshold] [-h help] [-n network_mode] [-m tls]"
    exit 0
}


## Bootstrap
## ----------------------------------------------------------
if [ ! -n "$1" ]; then
    help
fi

while [ -n "$1" ]; do
    case "$1" in
        -p)
	    PORT=$2
            shift
        ;;
        -t)
            ENTRY_THRESHOLD=$2
            shift
        ;;
        -n)
            NETWORK_MODE="true"
        ;;
        -m)
            let "TLS = $2 * 60"
            shift
        ;;
        -h)
            help
        ;;
        *)
	    help
        ;;
    esac
    shift
done

if ! [[ "${PORT}" =~ ^[0-9]+$ ]]; then
    echo "${PORT} is not found. "
    help
fi

if ! [[ "${ENTRY_THRESHOLD}" =~ ^[0-9]+$ ]]; then
    echo "Threshold parameter can be only integer"
    help
fi

if ! [[ "${TLS}" =~ ^[0-9]+$ ]]; then
    echo "TLS parameter can be only integer (minutes)"
    help
fi

## Get statistics by IP from nginx access log
if [ "${NETWORK_MODE}" == "true" ]; then
    ipRate=`getNetworksListByRate ${PORT}`
else
    ipRate=`getIpListByRate ${PORT}`
fi
ipRate=`getIpListByRate ${PORT}`
for ip in ${ipRate}; do
    echo ${ip}
    saveRuleTimestamp ${ip}
done

dropRule

exit 0
