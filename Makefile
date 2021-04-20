
all:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption.pvl -lib misc.pvl -lib sanity_queries.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl main.pv


equiv:
	proverif -lib primitives.pvl -lib format.pvl -lib key_schedule.pvl -lib secrecy_assumption.pvl -lib misc.pvl -lib client.pvl -lib client_ech.pvl -lib server.pvl main_equiv.pv
