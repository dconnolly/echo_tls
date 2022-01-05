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
