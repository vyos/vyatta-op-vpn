#!/bin/sh


rm -rf config m4
rm -f aclocal.m4 config.guess config.statusconfig.sub configure INSTALL

mkdir -p m4
autoreconf --force --install

rm -f config.sub config.guess
ln -s /usr/share/misc/config.sub .
ln -s /usr/share/misc/config.guess .
