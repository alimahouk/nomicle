# stop.sh | v0.1 | 19/08/2019 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is a convenience script to kill the Nomicle
# program suite.
# 
# USAGE
# This file should only be used if the programs
# were started using the start.sh script!
#
# On Unix-like systems (macOS, specifically), you may
# need to use sudo to execute this script.

PIDFILE_FORT=/tmp/fort.pid
if [ -f "$PIDFILE_FORT" ]; then
        kill -15 $(cat $PIDFILE_FORT)
        rm $PIDFILE_FORT
fi

PIDFILE_SEED=/tmp/seed.pid
if [ -f "$PIDFILE_SEED" ]; then
        kill -15 $(cat $PIDFILE_SEED)
        rm $PIDFILE_SEED
fi
