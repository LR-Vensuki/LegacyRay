#!/bin/sh
# LegacyRay for OS X: takes the daemon and its helpers out again, as root.
#   uninstall-helper.sh            keeps servers, subscriptions and settings
#   uninstall-helper.sh --purge    removes those too

PREFIX=/usr/local/legacyray
SYS="/Library/Application Support/LegacyRay"
PLIST=/Library/LaunchDaemons/com.legacyray.daemon.plist

if [ -f "$PLIST" ]; then launchctl unload "$PLIST" >/dev/null 2>&1; fi
# an engine whose daemon was killed outright is still running
killall -9 legacyray-engine >/dev/null 2>&1
rm -f /var/run/legacyray-engine.yaml /var/run/legacyray-engine.pid
if [ -x "$PREFIX/bin/legacyray-kick" ]; then "$PREFIX/bin/legacyray-kick" --awg-stop >/dev/null 2>&1; fi
pfctl -a com.apple/legacyray -F all >/dev/null 2>&1
# the daemon puts the system proxy back when it stops; a dead one leaves the
# old settings of each network service here (enabled, server, port, name)
if [ -f "$SYS/sysproxy.state" ]; then
  TAB=$(printf '\t')
  while IFS="$TAB" read -r on server port name; do
    [ -n "$name" ] || continue
    if [ "$server" != - ]; then networksetup -setsocksfirewallproxy "$name" "$server" "$port" >/dev/null 2>&1; fi
    if [ "$on" = 1 ]; then state=on; else state=off; fi
    networksetup -setsocksfirewallproxystate "$name" "$state" >/dev/null 2>&1
  done < "$SYS/sysproxy.state"
  rm -f "$SYS/sysproxy.state"
fi
rm -f "$PLIST" /var/tmp/legacyrayd.sock /var/tmp/legacyrayd.token
if [ "$(readlink /usr/local/bin/legacyrayctl 2>/dev/null)" = "$PREFIX/bin/legacyrayctl" ]; then
  rm -f /usr/local/bin/legacyrayctl
fi
rm -rf "$PREFIX"
if [ "$1" = "--purge" ]; then
  rm -rf "$SYS"
  rm -f /var/log/legacyray-system.log /var/log/legacyray-kick.log
fi
echo "legacyray-install: removed"
exit 0
