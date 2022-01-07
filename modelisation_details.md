# Modelisation details

#### Per-record nonce (Section 5.3 of TLS RFC).

In the RFC, the nonce given to the AEAD encryption algorithm should be computed
as follows:

1. The 64-bit record sequence number is encoded in network byte order and padded
  to the left with zeros to iv_length.

2. The padded sequence number is XORed with either the static client_write_iv or
  server_write_iv (depending on the role).

As ProVerif does not handle XOR, we weakened the the protection of the sequence
number by inputing only the sequence number. Hence the sequence number is not
protection by the `client_write_iv`.

We consider a sequence number for each different write key. Therefore, there is
a distinct sequence number for `client_write_key` and `server_write_key`.

For the sequence number related to 0-RTT and Handshake, we properly model the
incrementation of the sequences. For Application Data post handshake, we let
the attacker choose the value of the sequence number of we restrict ProVerif to
(bi)traces where the sequence number is used only once. Hence, we consider strictly
more behaviors than in reality as it allows messages to be sent with a non-increasing
sequence order.

#### 0-RTT Early data

We model the fact that clients and servers can send 0-RTT Early data. We do however
simplify the management of early data with the Client Hello. In particular, we do not
include in the client hello an `early_data` extension. Similarly, the client never sends
an EndOfEarlyData message to the server: It would corresponds to a server and client
that can always sends early data, even after the end of the Handshake.
We do this simplification to reduce the complexity of our model (in size and verification
time) and thus to allow ProVerif to finish in "reasonable" time.

#### Post Handshake Authentication

For the same reasons as 0-RTT Early Data, we do not include the Post Handshake Authentication
extension in the Client Hello. When the option is activated, the client is always
willing to do Post Handshake Authentication.

#### Offers of CipherSuite and DH groups

The client will always only offer a single cipher suite and DH group to the server.
The attacker will choose however which cipher suite and group the client offers.

#### Generation of resumption ticket

The server will always send a `[NewSessionTicket]` message at the send of the
handshake. We do not model multiple tickets. Clients will be able to use the
pre shared keys derived from this ticket in later handshakes.

#### Rejected ECH and HRR

In the RFC, it is indicated that, in the case of a rejected ECH,  the frontend may
send an "encrypted_client_hello" with a payload of 8 random bytes in its HRR
message. We do not model that last part, as it is a MAY condition.

#### Pre Shared Key options

We also simplify lightly the options for each pre shared key: We consider that
all pre shared keys allow for early data. Moreover, we do not assign a different
category for external and resumption pre shared key. As such, we consider a single
label when computing the early_secret for all pre shared keys.

#### Some notes on the structure of `client.m4.pvl` and `server.pvl`

To simplify the writing, we split the client and server processes into several subprocesses. For instance, in `client.m4.pvl`, the subprocess `process_server_certificate_message` handles the `server_hello` message, the subprocess handles the `finished_message` of the server, etc.

A naive way to encode the main process of the client would have been to call the subprocess directly. However, due to the different scenarios we consider, this would yield a gigantic process due to the numerous conditional branching. To speedup the verification time, some of the processes at not called directly but their arguments are passed through a private channel. For example, the process `process_server_certificate_message` inputs its arguments on the private channel `ch_client_CRT` and outputs its results on the private channel `ch_client_FIN`.

Semantically, both encoding are completely equivalent but passing the arguments through private channels decreases significantly the verification time.

It has however a drawback due to ProVerif internal abstraction: There is a loss of precision which may lead to false attacks. We use ProVerif axioms to avoid such false attacks. More details below.

### Justification of axioms

In this section, we do not refer as axioms the property written in the security property main files (e.g. `secrecy.pv`).
```
axiom c_dom,c_dom',s_dom,s_dom':domain,h,h_alg,h_alg':hash_alg,id,id':identityPsk,cr,sr:bytes32,old_psk,psk,psk':preSharedKey,idP,idP',id_s,id_c:idProc,is_safe,is_safe':bool,i:nat,e:element,g:group,x:bitstring,s:seed,log:bitstring, s_pkey,c_pkey:pubkey;
  table(pre_shared_keys(c_dom,s_dom,h,id,psk,idP,is_safe)) ==> attacker(id) || id = mk_idpsk(s_dom,h,psk);
  table(pre_shared_keys(c_dom,s_dom,h,id,psk,idP,true)) ==> id = mk_idpsk(s_dom,h,psk);
  table(pre_shared_keys(c_dom,s_dom,h,id,psk,idP,true)) && attacker(psk);
  table(pre_shared_keys(c_dom,s_dom,h,id,psk,idP,is_safe)) && attacker(psk) ==> is_safe = false;
  table(pre_shared_keys(c_dom,s_dom,h,id,psk,idP,is_safe)) ==> psk <> NoPsk && psk <> b2psk(zero);
  ...
```
Though they are declared as axioms, we actually prove these properties in the main file `lemmas_reachability.pv` (in the corresponding folder within `security_properties`). There are two reasons why we separated them: First by declaring them with a `lemma`, ProVerif would have reproved them everytime for each security property. Second, and most importantly, the ProVerif options to prove these properties and the main security properties are incompatible (different `nounif` declarations required).



All the other axioms we rely on in our model follow the same pattern: they add back some precision that were lost by ProVerif due to its internal abstraction when proving a protocol (namely translation into Horn clauses).

The axioms we added follow the vein of the transformations introduced by the frontend [GSVerif](https://sites.google.com/site/globalstatesverif/) and by the recent version of ProVerif:

In `main_processes.pvl`, we defined the following function:
```
  letfun mkprecise(x:bitstring) =
    if do_precise
    then new st[]:stamp; event PreciseInput(st,x); ()
    else ()
  .
```
This function is for instance used in `main_process.pvl` as follows:
```
  in(io,comp_psk:bool);
  event Same(bool2b(comp_psk));
  let () = mkprecise(bool2b(comp_psk)) in
  standard_client(id_client,use_psk,comp_psk,send_kex,c_dom,s_dom,tls_g,tls_h,tls_a)
```
Finally, in `proof_helper_reachability.pvl`, we added the following axiom:
```
axiom st:stamp,x,x':bitstring;
  event(PreciseInput(st,x)) && event(PreciseInput(st,x')) ==> x = x'.
```
In the semantics of a process, in **one execution trace**, the variable `comp_psk` cannot take two different values. Of course, `comp_psk` can take different values over several execution trace but within a single trace, `comp_psk` is instantiated only once since the input is executed only once. However, due to the abstractions made by ProVerif, the tool does not consider this simple and trivial property. It is the cause of many of the false attacks yielded by the tool. This axiom encodes back this property into ProVerif.

Why is the axiom correct ? Note that the function `mkprecise` always generates a fresh name `st` before adding the event `PreciseInput(st,x)`. Since `st` is fresh at each call of `mkprecise`, we can deduce that within **one execution trace**, no two different events `PreciseInput` can be executed with the same `st`. The axiom thus states that if within a trace, `PreciseInput(st,x)` and `PreciseInput(st,x')` can be matched to events that have been executed then it fact, they match to exactly the same event which implies that `x = x'`.

This encoding and axiom is in fact exactly how the option `[precise]` which can be added next to an input is encoded internally in ProVerif. We made our own version with the function `mkprecise` to be able to activate/deactivate it by just changing the value of the variable `do_precise`.


The other main axiom we use is the following:
```
axiom ch:channel,st,st':stamp,id,id':idProc;
  event(PreciseIdProcess(ch,id,st)) && event(PreciseIdProcess(ch,id,st')) ==> st = st';
  event(PreciseIdProcess(ch,id,st)) && event(PreciseIdProcess(ch,id',st)) ==> id = id'
.
```
This axiom relates to how we encoded the client and server by passing arguments private channels through private channels, as previously mentioned. Typically, when the main process of the client (same thing for the server) is called, we generate a process identity which is a name (of type `idProc`) that is passed through all the subprocesses and which identify inside a subprocess which *original main process* is *calling* the subprocess.
```
(* TLS*)
!
new id_tls_client:idProc;
(* Domains *)
in(io,s_dom:domain);
in(io,c_dom:domain);

run_tls_client(id_tls_client,c_dom,s_dom)
```
In this extract of `secrecy.pv`, each client process is run with a fresh `id_tls_client` identifier.

##### What does the axioms ensure ?

An important observation crucial to the soundness of our axiom is that each main process only *call* a specific subprocess only ***once at most***, never more. For example, the subprocess `receive_server_finished_message` corresponding to the client receiving and processing the Finished message from the server is only called once by the client. Thus, if we look at the code of the subprocess:
```
let receive_server_finished_message =
  !
  in(ch_client_FIN,(id_client:idProc,ArgsClientFIN(
    cr,sr,h_alg,a_alg,
    c_dom,s_dom,s_pkey,cert_req,
    psk,safe_psk,comp_psk,
    master_secret,chk,seq_client,shk,seq_srv,cfin,sfin,
    cur_log
  )));
  (* Begin Proof Helper *)
  new st[]:stamp;
  event PreciseIdProcess(ch_client_FIN,id_client,st);
  ...
```
no two different messages can be sent on the private channel `ch_client_FIN` with the same identity process `id_client` (otherwise it would imply the the main process would have ***called*** the subprocess twice, which is syntactically impossible).

By creating a fresh stamp `st` before calling the event, we know that, as in the previous axiom, that if two events have the same stamps, then they are necessarily the same event. This corresponds to the second part of the axiom:
```
event(PreciseIdProcess(ch,id,st)) && event(PreciseIdProcess(ch,id',st)) ==> id = id'
```
The first part of the axiom expresses the fact that  for a given subprocess (here identified by the private channel `ch`on which it expects its arguments), if two events have the same identity process then it must have been exactly the same event, hence their stamp should be equal.
```
event(PreciseIdProcess(ch,id,st)) && event(PreciseIdProcess(ch,id,st')) ==> st = st'
```

All other axioms used in our model are typically combinations of these two properties (unicity of variable instantiation and unicity of subprocess call by a main process).
