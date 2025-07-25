cd /tmp
WORKDIR=$(mktemp -d)
cd "$WORKDIR"

XDG_CACHE_HOME=/tmp/pwndbg-cache gdb -q /narnia/narnia8 -ex "source /opt/pwndbg/gdbinit.py"