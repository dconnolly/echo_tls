# Verification of TLS 1.3 with ECH extension

### File structure

The folder `librairies` contains all files describing the protocol. They are all
Proverif librairies and so must be call with the option `-lib xxx`.
- `primitives.pvl`: Description of the cryptographic primitives.
- `format.pvl`: Description of the message format and different element used in the protocol (DH key shares, pre shared keys, certificates, ECH configurations, Handshake messages and extensions)
- `key_schedule.pvl`: Functions generating the keys used in the TLS handshake (section 7.1 of TLS RFC).
- `tls_functions.pvl`: Some functions used by the client and server during the TLS handshake (e.g. generation of `client_hello`, pre shared key extension)
- `ech_functions.pvl`: Some functions specifically used by ECH client and server (e.g. generation of `AAD`, `accept_confirmation`, `encrypted_client_hello`)

The main processes are defined in the following 3 files.
- `client.m4.pvl`: The client process.
- `server.pvl`: The server process
- `main_process.pvl`: Processes generating the honest and dishonest (i.e. compromised) keys and the main processes to call, i.e. `all_internal_processes`, `run_ech_client`, `run_standard_client`, `run_server`.

The files `proof_helper_reachability.pvl` and `proof_helper_equivalence.pvl` contains declarations of some axioms and ProVerif declarations that helps ProVerif terminate and avoid false attacks. The axioms are properties that are true for all traces of the protocols (hence they are not restrictions). More details in `proof_helper.md`.

All the security properties we prove are defined in the folder `security_properties`, each security property having its own folder that contains the following files:
- `Makefile`: To run the verification
- `config.pvl`: Contains all the different configurations options (e.g. allow HRR, Post handshake new session, early data, compromised keys, ...)
- `config_proof_helper.pvl`: Additional proof helpers specific to the security property. The variables `select_client_certificate_by_restriction`, `select_server_certificate_by_restriction`, `select_client_pre_shared_key_by_restriction` and `select_server_pre_shared_key_by_restriction` should not be modified. The other booleans may be modified but it may make ProVerif slower or yield a false attack. Intuitively, when the variables for precision are set to true, it increases the precision (hence yielding less false attacks) but slows down ProVerif.
- `my_security_property.pv`: the main file for the security property `my_security_property`. It contains the main process as well as the query. The file also contains some axioms that are properties proved in the security properties folder `lemmas_reachability`. As ProVerif needed different proof settings to handle these particular properties, we separated them from the main properties.

For equivalence properties, there is an additional main file for the case where the server does not generates new ticket (faster verification).

### Some notes of the structure of `client.m4.pvl` and `server.pvl`

To simplify the writing, we split the client and server processes into several subprocesses. For instance, in `client.m4.pvl`, the subprocess `process_server_certificate_message` handles the `server_hello` message, the subprocess handles the `finished_message` of the server, etc.

A naive way to encode the main process of the client would have been to call the subprocess directly. However, due to the different scenarios we consider, this would yield a gigantic process due to the numerous conditional branching. To speedup the verification time, some of the processes at not called directly but their arguments are passed through a private channel. For example, the process `process_server_certificate_message` inputs its arguments on the private channel `ch_client_CRT` and outputs its results on the private channel `ch_client_FIN`.

Semantically, both encoding are completely equivalent but passing the arguments through private channels decreases significantly the verification time.

It has however a drawback due to ProVerif internal abstraction: There is a loss of precision which may lead to false attacks. We use ProVerif axioms to avoid such false attacks. More details in `proof_helper.md`.

### Verifying the security properties


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
