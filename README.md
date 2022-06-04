# PING_log_analyzer
Simple utility for collecting statistics from results of PING.
Requires Python 3.6+

### Usage
0. (for *NIX): Make ping_log_analyze.py executable.
1. Save your PING results to text file (for example, by redirecting standart output to file using tee: `ping 192.168.1.1 | tee ping_router.log`).
2. Provide log file to the utility: `./ping_log_analyze.py ping_router.log`

Also has some options which can be listed using `-h` (`--help`) option.