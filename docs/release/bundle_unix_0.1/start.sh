# start.sh | v0.1 | 16/08/2019 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is a convenience script to start the Nomicle
# programs.
#
# USAGE
# You can pass in one argument to set as your identity
# token.
# e.g. $ ./start.sh foobar
#
# On Unix-like systems (macOS, specifically), you may
# need to use sudo to execute this script.

if [ $# -eq 1 ]; then
        PATH_UNIX_ID=/usr/local/share/fid/id
        PATH_UNIX_ID_DIR=/usr/local/share/fid

        mkdir -p $PATH_UNIX_ID_DIR
        echo $1 > $PATH_UNIX_ID
fi

# Redirect program output as required; default is no output.
# The PID of each process is written to /tmp.

FILE_FORT=fort.py
if [ -f "$FILE_FORT" ]; then
        if [ $# -eq 1 ]; then
                nohup python3 fort.py -i $1 </dev/null >/dev/null 2>&1 & echo $! > /tmp/fort.pid
        else
                nohup python3 fort.py </dev/null >/dev/null 2>&1 & echo $! > /tmp/fort.pid
        fi
fi

FILE_SEED=seed.py
if [ -f "$FILE_SEED" ]; then
        nohup python3 seed.py </dev/null >/dev/null 2>&1 & echo $! > /tmp/seed.pid
fi
