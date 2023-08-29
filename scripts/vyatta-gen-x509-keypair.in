#!/bin/bash
CN=$1
genkeypair (){
  openssl req -new -nodes -keyout /config/auth/$CN.key -out /config/auth/$CN.csr -config /opt/vyatta/etc/key-pair.template
}
if [ -f /config/auth/$CN.csr ]; then
  read -p "A certificate request named $CN.csr already exists. Overwrite (y/n)?"
  [[ $REPLY != y && $REPLY != Y ]] || genkeypair
else 
  genkeypair
fi
