#! /bin/sh
# /etc/init.d/dns2tcp
#

touch /var/lock/dns2tcp

# Carry out specific functions when asked to by the system
case "$1" in
  start)
    echo "Starting dns2tcp forwarding DNS server"
    cd /etc/dns2tcp
	./dns2tcp >/var/log/dns2tcp.log 2>&1 &
	echo $!
    ;;
  stop)
    echo "Stopping dns2tcp forwarding DNS server"
    pkill dns2tcp
    ;;
  *)
    echo "Usage: /etc/init.d/dns2tcp {start|stop}"
    exit 1
    ;;
esac

exit 0
