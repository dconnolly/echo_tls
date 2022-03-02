all:
	echo "Two options:"
	echo "  insert     Proof when the ticket are generated and re-inserted"
	echo "  noinsert   Proof when the ticket are generated but not re-inserted"
	echo ""

noinsert:
	mkdir -p ../../generated_libraries
	m4 -D PSK_or_random -D PSK_or_random_NoInsert ../../libraries/client.m4.pvl > ../../generated_libraries/client_psk_or_random_no_insert.pvl
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
	-lib ../../generated_libraries/client_psk_or_random_no_insert.pvl \
	-lib ../../libraries/main_processes.pvl \
	-lib ../../libraries/proof_helper_equivalence.pvl \
	psk_or_random_no_insert.pv

insert:
	mkdir -p ../../generated_libraries
	m4 -D PSK_or_random ../../libraries/client.m4.pvl > ../../generated_libraries/client_psk_or_random.pvl
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
	-lib ../../generated_libraries/client_psk_or_random.pvl \
	-lib ../../libraries/main_processes.pvl \
	-lib ../../libraries/proof_helper_equivalence.pvl \
	psk_or_random.pv
