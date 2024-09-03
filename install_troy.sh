#! /bin/bash

cd troy-nova/build
sudo cp src/libtroy.so /usr/local/lib/libtroy.so.0.2.1
sudo ln -s /usr/local/lib/libtroy.so.0.2.1 /usr/local/lib/libtroy.so.0
sudo ln -s /usr/local/lib/libtroy.so.0 /usr/local/lib/libtroy.so
