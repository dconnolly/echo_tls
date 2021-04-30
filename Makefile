
all:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption.pvl -lib misc.pvl -lib sanity_queries.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl main.pv


privacy_backend:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption_equiv.pvl -lib misc.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl privacy_backend.pv

privacy_backend_weak:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption_equiv.pvl -lib misc.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl privacy_backend_weak_compromise.pv

privacy_backend_dC_hS:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption_equiv.pvl -lib misc.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl privacy_backend_dC_hS.pv

privacy_backend_dC_dS:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption_equiv.pvl -lib misc.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl privacy_backend_dC_dS.pv
