#!/bin/sh
cd ipdbg

python3 build.py clean --all
python3 build.py build

cp build/lib.*/ipdbg.*.so ../

cd ..
