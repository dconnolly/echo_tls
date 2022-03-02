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

The files `proof_helper_reachability.pvl` and `proof_helper_equivalence.pvl` contains declarations of some axioms and ProVerif declarations that helps ProVerif terminate and avoid false attacks. The axioms are properties that are true for all traces of the protocols (hence they are not restrictions). More details in `modelisation_details.md`.

All the security properties we prove are defined in the folder `security_properties`, each security property having its own folder that contains the following files:
- `Makefile`: To run the verification
- `config.pvl`: Contains all the different configurations options (e.g. allow HRR, Post handshake new session, early data, compromised keys, ...)
- `config_proof_helper.pvl`: Additional proof helpers specific to the security property. The variables `select_client_certificate_by_restriction`, `select_server_certificate_by_restriction`, `select_client_pre_shared_key_by_restriction` and `select_server_pre_shared_key_by_restriction` should not be modified. The other booleans may be modified but it may make ProVerif slower or yield a false attack. Intuitively, when the variables for precision are set to true, it increases the precision (hence yielding less false attacks) but slows down ProVerif.
- `my_security_property.pv`: the main file for the security property `my_security_property`. It contains the main process as well as the query. The file also contains some axioms that are properties proved in the security properties folder `lemmas_reachability`. As ProVerif needed different proof settings to handle these particular properties, we separated them from the main properties.

For equivalence properties, there is an additional main file for the case where the server does not generates new ticket (faster verification).

### Verifying the security properties

[ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) should be installed before using our script. Do **not** use the source package of ProVerif 2.04. Indeed, to run properly our models in ProVerif, we asked the developers of ProVerif to add some features to make lemmas and axioms more expressive, which they did. In particular, we rely in our model on the fact that attacker predicates can be used in the conclusion of a lemma and of an axiom. This is not possible in ProVerif 2.04 and these features are now currently available only on the official [ProVerif Gitlab](https://gitlab.inria.fr/bblanche/proverif/-/tree/improved_scope_lemma).

To obtain the source code, you can either:
- Go to the official [ProVerif Gitlab](https://gitlab.inria.fr/bblanche/proverif/-/tree/improved_scope_lemma). Select the branch `improved_scope_lemma` and download the source code from the interface.
- Clone the repo using `git clone https://gitlab.inria.fr/bblanche/proverif.git` (for HTTPS access) or `git clone git@gitlab.inria.fr:bblanche/proverif.git` (for SSH access). Run `git checkout improved_scope_lemma`.

To install ProVerif, you need to run the script `./build` from the subfolder `proverif`. Finally, our script `run_bench` and our `Makefile` assumes that the executable `proverif` is accessible in your PATH.

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
- `<S>` is a number from 1 to 3 corresponding to the compromised keys, the groups and ciphersuites
- `<B>` is a number from 1 to 4 corresponding to the behavior of the clients and servers
- `<A>` is a number from 1 to 4 corresponding to the agents considered.

When the option `PV` is given, ProVerif will run and its output is given in the standard output. When the option `PV` is omitted, the output of ProVerif is recorded in the folder `tests`. It will also record a short summary of the memory consumption and execution time in a file `result.txt` inside the folder of the corresponding security property.

###### Functionalities scenarios

The functionalities (parameter `<F>` above) are as follows:

| `<F>` | HRR | Tickets | PH Data | PH Auth | Early Data |
| - | --- | ------- | ------- | ------- | ---------- |
| 1 | *no* | *no* | *no* | *no* | *no* |
| 2 | *no* | **yes** | *no* | *no* | *no* |
| 3 | *no* | **yes** | **yes** | *no* | *no* |
| 4 | *no* | **yes** | **yes** | **yes** | *no* |
| 5 | *no* | **yes** | **yes** | **yes** | **yes** |
| 6 | **yes** | *no* | *no* | *no* | *no* |
| 7 | **yes** | **yes** | *no* | *no* | *no* |
| 8 | **yes** | **yes** | **yes** | *no* | *no* |
| 9 | **yes** | **yes** | **yes** | **yes** | *no* |
| 10 | **yes** | **yes** | **yes** | **yes** | **yes** |

In the above table, when **HRR** is set to *no* then clients send their DH key share with the DH group and servers do not send Hello Retry Request and abort instead. When set to **yes**, the attacker chooses if clients send their DH key share with the DH group and servers send Hello Retry Request if clients do not send their DH key share.

When **Tickets** is set to **true**, the server generates a new ticket at the end of each handshake, and clients can reused the PSK obtained from a ticket in another session. When set to *no*, server never generates tickets and clients are not expecting to receive a ticket.

When **PH Data** is set to **true**, clients and Servers can send/receive Post Handshake Data. When set to *no*, they do not send nor expect Post Handshake Data.

When **PH Auth** is set to **true**, servers can request Post Handshake Authentication and clients reply accordingly by sending a certificate. When set to *no*, servers do not request Post Handshake Authentication and clients are not expecting it.

When **Early Data** is set to **true**, clients and servers can send/receive 0-RTT early data. When set to *no*, clients and servers do not send nor expect 0-RTT early data.

###### Compromised Keys, Cipher suites and groups scenarios

| `<S>` | Ech Config | External PSK | Ticket PSK | Certificate | Group, CS |
| - | --- | ------- | ------- | ------- | ---------- |
| 1 | **choice** | **choice** | **choice** | *no* | *fixed* |
| 2 | **choice** | **choice** | **choice** | **choice** | *fixed* |
| 3 | **choice** | **choice** | **choice** | **choice** | **choice** |

When the parameter of a key is set to **choice**, then the attacker is allowed to compromise keys of this type. When set to *no*, all keys of this type is uncompromised (hence not directly known by the attacker). For the DH group and cipher suite, when set to *fixed*, the ciphersuites and DH groups are not choosen by the attacker. They are the same for all TLS handshake. The ciphersuites and groups in ECH configurations differs from the ones used in the TLS handshake. When set to **choice**, the ciphersuites and DH groups are choosen by the attacker for each session.

###### Agent behaviors

| `<B>` | PSK | Req Client Cert | Grease | Send DH key share |
| - | --- | ------- | ------- | ------- |
| 1 | *no* | *no* | *no* | **choice** |
| 2 | **choice** | *no* | *no* | **choice** |
| 3 | **choice** | **choice** | *no* | **choice** |
| 4 | **choice** | **choice** | **choice** | **choice** |

When **PSK** is set to **choice**, the attackers choose whether clients and servers send and accept pre shared keys respectively. When set to *no*, clients and servers never send nor accept pre shared keys.

Similar meaning for the other parameters where **Req Client Cert** refers to servers requesting client certificate during the main handshake, **Grease** refers to ECH clients using GREASE and **Send DH key share** refers to clients sending their key share in the first client hello (if they don't it will trigger an HRR reply by the server, unless the parameter **HRR** is set to *no*).

###### Agent behaviors

| `<A>` | TLS Clients | ECH Clients | TLS Server | ECH Server |
| - | --- | ------- | ------- | ------- |
| 1 | **yes** | *no* | **yes** | *no* |
| 2 | *no* | **yes** | *no* | **yes** |
| 3 | *no* | **yes** | **yes** | **yes** |
| 4 | **yes** | **yes** | **yes** | **yes** |

The parameter specify where the property is proved in the presence of specific agents. When set to **yes**, we always consider an unbounded number of sessions.

### Verification results

The details for all of verification results can be found in the files `result.txt` of each security property.
The results were obtain on a  64 X AMD 3.8Ghz-CPU server with 515 GB of RAM. Note that ProVerif is not a multicore
program so run on a single processor.
For example, in the result file of the `authentication` folder:

> authentication - Scenario F4 S2 B3 A2 - 2 true queries - Time 42:28.20 - Memory 80406840k
>
> authentication - Scenario F4 S2 B3 A4 - 2 true queries - Time 1:09:13 - Memory 122006684k
>
> authentication - Scenario F9 S2 B2 A2 - 2 true queries - Time 1:58:52 - Memory 69985712k
>
> authentication - Scenario F9 S2 B2 A4 - 0 true queries - Time 1:32:41 - Memory 92383056k Command terminated by signal 9

Each line corresponds to a scenario with the execution time, `1:32:41` means 1h 32min and 41s, whereas `42:28.20` means 42min 28s and 20 ms. Memory is given in kilo bytes. Note that when the line contains `Command terminated`, then it indicates that it was terminated either by running out of time (48h max) or by running out of memory. As we ran several script in parallel, file that had been terminating due to lack of memory was usually using between 100GB to 300GB of RAM. As the scenarios are mostly defined in increasing order of difficulties in term of verification, we avoided running more complex scenario than the one that were already timing/memory out.

All our results can be found in the files `ECH_verification.numbers` or `ECH_verification_results.pdf`.
