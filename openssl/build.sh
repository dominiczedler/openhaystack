
#!/bin/bash
cd "$(dirname "$0")"

rm -rf release
mkdir release
gcc -L/opt/homebrew/opt/openssl@3/lib -I/opt/homebrew/opt/openssl@3/include -o release/generate_keypairs generate_keypairs.c 
./release/generate_keypairs 
