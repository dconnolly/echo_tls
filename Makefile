
LIBDIR= libraries

LibReach= primitives.pvl format.pvl key_schedule.pvl secrecy_assumption.pvl misc.pvl client.pvl client_ech.pvl server.pvl main_processes.pvl
LibEquiv= primitives.pvl format.pvl key_schedule.pvl secrecy_assumption_equiv.pvl misc.pvl client.pvl client_ech.pvl server.pvl main_processes.pvl

FilesReach=$(addprefix -lib $(LIBDIR)/,$(LibReach))
FilesEquiv=$(addprefix -lib $(LIBDIR)/,$(LibEquiv))

all:
	proverif $(FilesReach) -lib $(LIBDIR)/sanity_queries.pvl sanity_checks.pv

scenario:
	./prepare
	@time proverif $(FilesEquiv) privacy_backend_SCENARIO$(S).pv > log_privacy_backend_S$(S).txt
	@time proverif $(FilesEquiv) privacy_client_SCENARIO$(S).pv > log_privacy_client_S$(S).txt
	@time proverif $(FilesEquiv) privacy_client_ech_SCENARIO$(S).pv > log_privacy_client_ech_S$(S).txt
	@time proverif $(FilesEquiv) strong_secrecy_inner_SCENARIO$(S).pv > log_strong_secrecy_inner_S$(S).txt

privacy_backend:
	proverif $(FilesEquiv) generated_models/privacy_backend_SCENARIO1.pv

privacy_client_ech:
	proverif $(FilesEquiv) privacy_client_ech_SCENARIO3.pv

privacy_client:
	proverif $(FilesEquiv) privacy_client_SCENARIO3.pv

strong_secrecy_inner:
	proverif $(FilesEquiv) strong_secrecy_inner_SCENARIO3.pv
