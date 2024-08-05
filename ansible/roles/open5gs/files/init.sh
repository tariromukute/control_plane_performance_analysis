#!/bin/bash

imsi=999700000000001

for i in {1..2}
do
    ./open5gs-dbctl add  $[imsi + i] 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
    echo "Registered IMSI $[imsi + i] times"
done