#!/bin/bash
source_host=20.26.39.219
source_port=20011
source_db=0
target_host=20.26.39.198
target_port=20011
target_db=0
redis_client="/app/redis/bin/redis-cli"

#copy all keys without preserving ttl!
START_TIME=$(($(date +%s%N)/1000000))
END_TIME=$(($(date +%s%N)/1000000))
${redis_client} -c -h ${source_host} -p ${source_port} -n ${source_db} keys \* | while read key; do echo "Copying $key"; ${redis_client} --raw -c -h ${source_host} -p ${source_port} -n ${source_db} DUMP "$key" | head -c -1|${redis_client} -x -c -h ${target_host} -p ${target_port} -n ${target_db} RESTORE "$key" 0; done
COST_TIME=$[${END_TIME} - ${START_TIME}]
echo "Sync rdb cost time=${COST_TIME}"