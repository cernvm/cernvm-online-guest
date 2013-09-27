#!/bin/bash
##################################################
# CernVM Online Contextualization Scripts v0.1
# ------------------------------------------------
# This script is a launcher for cernvm-online.sh
# since we cannot specify command-line parameters
# in /etc/inittab.
##################################################

# Start cernvm-online.sh in login mode
/usr/sbin/cernvm-online.sh login
