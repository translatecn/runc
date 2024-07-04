make release
ssh -t root@vm rm -rf /Users/acejilam/Desktop/runc/*
ssh -t root@vm rm -rf /tmp/*
ssh -t root@vm rm -rf /Users/acejilam/Desktop/runc/.*
ssh -t root@vm mkdir -p /Users/acejilam/Desktop/runc
rsync -aPc . root@vm:/Users/acejilam/Desktop/runc
ssh -t root@vm rm -rf /Users/acejilam/Desktop/runc/.idea
ssh -t root@vm bash /Users/acejilam/Desktop/runc/debug.sh