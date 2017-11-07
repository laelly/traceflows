#!/bin/bash
APP_NAME="Inventory WebApp"
SCRIPT_DIR=`dirname $0`/../
# HYPNOTOAD_BIN=/usr/local/bin/hypnotoad
HYPNOTOAD_BIN=hypnotoad
PERL_SCRIPT="${SCRIPT_DIR}/MyApp.pl"
PID="${SCRIPT_DIR}/pid/MyApp.pid"


RETVAL=0
start() {
	echo "Starting ${APP_NAME}... "	
	${HYPNOTOAD_BIN} ${PERL_SCRIPT}
}

test() {
	echo "Testing ${APP_NAME}... "	
	${HYPNOTOAD_BIN} -t ${PERL_SCRIPT}
}

stop() {
	echo "Shutting down ${APP_NAME}... "
	# ${HYPNOTOAD_BIN} -s ${PERL_SCRIPT}
	/bin/kill -s TERM `/bin/cat ${PID}`
}

killme() {
	echo -n "Forcing ${APP_NAME} shutdown... "
	# SIGHUP	
	/bin/kill -s TERM `/bin/cat ${PID}`
	RETVAL=$?
	if [ $RETVAL -eq 0 ] ; then
		echo "Successfully killed ${APP_NAME}"
	else
		echo "Failed to kill ${APP_NAME}"
	fi
}

case "$1" in
	start)
		start
		;;
	stop)
		stop
		;;
	test)
		test
		;;
	restart)
		echo "Restarting ${APP_NAME} (hot deployment)..."
		start
		;;
	kill)
		killme
		;;
	*)
		echo "${APP_NAME} Startup script"
		echo "Usage: $0 {start|stop|restart|test|kill}"
		exit 1
esac

exit $RETVAL



