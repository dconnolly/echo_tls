all:
	echo "Two options:"
	echo "  ticket     Proof when allow_PH_new_session_ticket = true"
	echo "  noticket   Proof when allow_PH_new_session_ticket = false"
	echo ""
	echo "Warning: Do not run [noticket] when allow_PH_new_session_ticket = true "
	echo "otherwise it will never terminates. It is possible to run [ticker] when"
	echo "allow_PH_new_session_ticket = false but it will be slower."

noticket:
	mkdir -p ../../generated_libraries
	m4 ../../libraries/client.m4.pvl > ../../generated_libraries/client.pvl
	proverif \
	-lib config.m4.pvl \
	-lib ../../libraries/primitives.pvl \
	-lib ../../libraries/format.pvl \
	-lib ../../libraries/key_schedule.pvl \
	-lib ../../libraries/events.pvl \
	-lib config_proof_helper.m4.pvl \
	-lib ../../libraries/tls_functions.pvl \
	-lib ../../libraries/ech_functions.pvl \
	-lib ../../libraries/server.pvl \
	-lib ../../generated_libraries/client.pvl \
	-lib ../../libraries/main_processes.pvl \
	-lib ../../libraries/proof_helper_equivalence.pvl \
	privacy_backend_no_ticket.pv

ticket:
	mkdir -p ../../generated_libraries
	m4 ../../libraries/client.m4.pvl > ../../generated_libraries/client.pvl
	proverif \
	-lib config.m4.pvl \
	-lib ../../libraries/primitives.pvl \
	-lib ../../libraries/format.pvl \
	-lib ../../libraries/key_schedule.pvl \
	-lib ../../libraries/events.pvl \
	-lib config_proof_helper.m4.pvl \
	-lib ../../libraries/tls_functions.pvl \
	-lib ../../libraries/ech_functions.pvl \
	-lib ../../libraries/server.pvl \
	-lib ../../generated_libraries/client.pvl \
	-lib ../../libraries/main_processes.pvl \
	-lib ../../libraries/proof_helper_equivalence.pvl \
	privacy_backend.pv
