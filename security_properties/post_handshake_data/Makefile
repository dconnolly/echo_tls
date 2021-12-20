all:
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
	-lib ../../libraries/proof_helper_reachability.pvl \
	post_handshake_data.pv
