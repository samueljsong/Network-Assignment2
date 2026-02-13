PASSWORDS (Passwords are all abc), replace the password in shadow.txt
MD5
$1$BJRFpf63$C/P21/z/Hcs5XAilDRon01

bcrypt
$2b$05$24GkQym/epjStgdbGjwbWe73UmL81tiZNHW4ONge.Nn1SF6PZTuNO

SHA-256
$5$CH.Ps3Ft6UlwNspf$uZm51CsNVX2tLcEUHiQEbyGxpilUIihR2.LE3X97XfA

SHA-512
$6$2.0YP8kzwqhoUP80$7BS4ZuMd6dWGSTLlXl4Wh2NT1Z8aWxj9RPhehrL/YR2m785cY8NJVqbH549JR6Zl5R1TOLc7RnVKcwQjbwvpB1

yescrypt
$y$j9T$HmsV4a5JXiT7JrVgJeqy3.$kSiB1fYfH7aeTJPxH/XOeGLfjP2riLyUEhCZvRB2VX3



How to run
./controller.py -f shadow.txt -u someuser -p 5000 -b 2
./worker.py -c <controller_ip> -p 5000 -t 4

heartbeats should come out like this

[HB] delta_tested=15800 total_tested=47400 threads_active=4 rate=7900.2/s
