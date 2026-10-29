#!/bin/sh
set -eu
mount --make-rprivate /
mount --make-rshared /
exec /sbin/init
