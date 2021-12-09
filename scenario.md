# Description of the protocol and assumptions

## Assumptions

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

When the client select a PSK that allows early data, we only model one early
message `(Application Data)` sent by the client instead of a flow of messages.

Moreover, we do not model the fact that the server could send data before receiving the client `Finished`.

#### Offers of CipherSuite and DH groups

The client will always only offer a single cipher suite and DH group to the server.
The attacker will choose however which cipher suite and group the client offer.

#### Generation of resumption ticket

The server will always send a `[NewSessionTicket]` message at the send of the
handshake. We do not model multiple tickets. Clients will be able to use the
pre shared keys derived from this ticket in later handshakes.
