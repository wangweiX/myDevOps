#!/bin/bash
DIRC=/mydata/www
find  ${DIRC} -type f -exec chmod 644 {} \;
find  ${DIRC} -type d -exec chmod 755 {} \;