
LIBDIR= libraries

LibReach= primitives.pvl format.pvl key_schedule.pvl secrecy_assumption.pvl misc.pvl client.pvl client_ech.pvl server.pvl main_processes.pvl
LibEquiv= primitives.pvl format.pvl key_schedule.pvl secrecy_assumption_equiv.pvl misc.pvl client.pvl client_ech.pvl server.pvl main_processes.pvl

FilesReach=$(addprefix -lib $(LIBDIR)/,$(LibReach))
FilesEquiv=$(addprefix -lib $(LIBDIR)/,$(LibEquiv))

sanity:
	proverif $(FilesReach) -lib $(LIBDIR)/sanity_queries.pvl sanity_checks.pv

privacy_backend:
	proverif $(FilesEquiv) privacy_backend.pv
