# Verification of TLS 1.3 with ECH extension

The model follow the RFC https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-13
and https://tools.ietf.org/html/rfc8446.

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

To verify a security property, run the `Makefile` contained in the folder of the corresponding property. You can modify the file `config.pvl` in the folder to enable or disable some functionalities. An explanation for each variable setting is given as comment in `config.pvl`.

#### The `run_bench` script

The script `run_bench` allows to run specific preconfigured scenarios.
```
run_bench one <security_prop> <F> <S> <B> <A> [PV]
run_bench <type> <security_prop>
```
where:
- `<security_prop>` can be:
  - `secrecy`: Secrecy of `client_write_key` and `server_write_key` for Application Data record. Also includes synchronisation of `exporter_master_key` and `resumption master key`
  - `early`: Secrecy of the message and injective agreement for 0RTT data.
  - `auth`: Authentication between honest clients and servers.
  - `downgrade`: Downgrade resilient, i.e, if the client and server finished the handshake agreeing, and the client offered to do with an ECH configuration with a configuration accepted by the server then both client and server accepted ECH.
  - `key`: Key sequentially describing how pre shared key can be compromised.
  - `PHauth`: Post Handshake authentication.
  - `PHdata`: Secrecy of Post Handshake Application Data and injective agreement.
  - `Rlemma`: Some useful lemma to help ProVerif conclude.
  - `backend`: Privacy of the backend server.
  - `PSKorR`: Equivalence between pre shared key and a random.
  - `inner`: Strong secrecy of an extra extension in the inner client hello.
  - `ee`: Strong secrecy of encrypted extension sent by the server.
  - `anonymityTLS`: Anonymity and unlinkability of TLS clients.
  - `anonymityECH`: Anonymity and unlinkability of ECH clients.
- `<type>` can be `reach` or `equiv`. The type `reach` should only be used with `secrecy`, `early`, `auth`, `downgrade`, `key`, `PHauth`, `PHdata` and `Rlemma`. The type `equiv` should be only be used with `backend`, `PSKorR`, `inner`, `ee`, `anonymityTLS` and `anonymityECH`.
- `<F>` is a number from 1 to 10 corresponding to the functionalities
- `<S>` is a number from 1 to 3 corresponding to the safety of keys, the groups and ciphersuites
- `<B>` is a number from 1 to 4 corresponding to the behavior of the clients and servers
- `<A>` is a number from 1 to 4 corresponding to the agents considered.

When the option `PV` is given, ProVerif will run and its output is given in the standard output. When the option `PV` is omitted, the output of ProVerif is recorded in the folder `tests`. It will also record a short summary of the memory consumption and execution time in a file `result.txt` inside the folder of the corresponding security property.

The functionalities (parameter `<F>` above) are as follows:

|   | HRR | Tickets | PH Data | PH Auth | Early Data |
| - | --- | ------- | ------- | ------- | ---------- |
| 1 | no | no | no | no | no |
| 2 | no | yes | no | no | no |
| 3 | no | yes | yes | no | no |
| 4 | no | yes | yes | yes | no |
| 5 | no | yes | yes | yes | yes |
| 6 | yes | no | no | no | no |
| 7 | yes | yes | no | no | no |
| 8 | yes | yes | yes | no | no |
| 9 | yes | yes | yes | yes | no |
| 10 | yes | yes | yes | yes | yes |

| 1 | Content Cell  |
| 2 | Content Cell  |




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
