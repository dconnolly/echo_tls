To run the different scenarios, use the executable run_bench. It will generates files in the two folder generated_models and generated_librairies. The folder generated_models will contain the main proverif file that is executed (it also contain the full proverif command that is run).

The model follow https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-13

#### Syntax to follow:

In the following, the optional PV run proverif and display its output. Without it, it only check that the value corresponds to the expected output.

<n> represents the scenario and be equal to 1 up to 5.

-- To run the sanity check:

./run_bench sanity [PV]
./run_bench sanity_nohrr [PV]

-- To run the privacy of the backend

* With PSK not reinjected

./run_bench backend <n> [PV]
./run_bench backend_nohrr <n> [PV]

* With PSK reinjected

./run_bench backend_full <n> [PV]
./run_bench backend_full_nohrr <n> [PV]

-- To run the strong secrecy of the extension in the inner client hello

* With PSK not reinjected

./run_bench inner <n> [PV]
./run_bench inner_nohrr <n> [PV]

* With PSK reinjected

./run_bench inner_full <n> [PV]
./run_bench inner_full_nohrr <n> [PV]

-- To run the privacy / unlinkability of the TLS client

* With PSK not reinjected

./run_bench client <n> [PV]
./run_bench client_nohrr <n> [PV]

* With PSK reinjected

./run_bench client_full <n> [PV]
./run_bench client_full_nohrr <n> [PV]

-- To run the privacy / unlinkability of the ECHO client

* With PSK not reinjected

./run_bench client_ech <n> [PV]
./run_bench client_ech_nohrr <n> [PV]

* With PSK reinjected

./run_bench client_ech_full <n> [PV]
./run_bench client_ech_full_nohrr <n> [PV]

-- To run the real or random secrecy of the generated PSK

./run_bench ror <n> [PV]
./run_bench ror_nohrr <n> [PV]



There is after the files for the scenario that Karthik requested (the one that start with main_):

./run_bench main_client [PV]         (Privacy client TLS only)
./run_bench main_ror [PV]            (Real or random PSK client TLS only)
./run_bench main_backend [PV]        (Privacy of the backend server, ECH client only)
./run_bench main_inner [PV]          (Strong secrecy of the extension in the inner client hello, ECH client only)
./run_bench main_client_ech [PV]     (Privacy client ECH only)
