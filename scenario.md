# Description of the protocol and modelisation details

## Modelisation details

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

## Description of the protocol

### Generic options

Despite some of simplifications, the model is still sometimes too large for ProVerif to
handle in reasonable times. So we defined generic configurations in `config.m4.pvl` that
define some global constant to restrict the scenarios we consider:
- `allow_HRR`: When `false`, an honest client will always send its key share with the group. Moreover, an honest server will never send a HRR request.
- `allow_early_data`: When `false`, honest clients and servers will never send or try to receive
early data.
- `allow_PH_data`: When `false`, honest clients and servers will never send or try to receive Post Handshake Application Data.
- `allow_PH_authentication`: When `false`, honest servers will request post handshake authentication and honest clients will never wait for one.
- `allows_compromised_ticket`: When `false`, the client never leak the pre shared keys derived from the tickets. Otherwise, when `true`, the attacker decides when to compromise or not a key.

To speed up the verification time, it important to deactivate options on both client and server, even if it is always the same role that initiates the communication. For exemple, in the case of HRR, we force client to always send their key share but by also deactivating the fact that a server will not send an HRR request, we avoid scenarios where it's the attacker that triggers an HRR response from the server.

### The server

We consider a single process to model both an ECH server and a TLS server. The server process takes the following arguments:
- `use_ech`: Indicates if it is an ECH server (`true`) or a TLS server (`false`)
- `use_psk`: Indicates if the server is willing to accept pre shared keys
- `req_cert`: Indicates if the server will request a client certificate.
- `accept_ED`: Indicates if the server will accepts early data in 0-RTT.
- `use_postHS`: Indicates if the server will ask for post handshake. authentication in the case the client is willing to do so too.
- `send_data`: Indicates if the server will send and receive Application Data in post handshake.
- `tck_ED`: Indicates if the pre shared key derived from the ticket generated at the end of the handshake allows 0-RTT.
- `s_dom`: The domain of the server.
- `tls_g,tls_h,tls_a`: the DH group and ciphersuite accepted by the frontend / TLS server.
- `backend_g,backend_h,backend_a`: the DH group and ciphersuite accepted by the backend server.
- `ee_extra`: an extra extension that will be send in the EncryptedExtension message.

##### The server process step by step

We explain here what the server is doing. It's almost faithful description in english of the ProVerif process, as it might be easier to read than the code itself.

1. When receiving a client hello from the public network, the server checks that:
  - it's a TLS 1.3 version (otherwise raise unexpected_message)
  - the SNI corresponds to s_dom (otherwise raise handshake_failure)
2. If the server is a TLS Server of if it's an ECH Server but no ECH extension
  is found in the client hello then the server acts as a TLS server (go to step 4)
3. Otherwise the server acts as a frontend and select an ECHConfig that he is willing to accept `ech_conf`. It proceeds as follows:
    - checks that the encrypted_client_hello `ech_ext` is of type outer.
    - checks that ech_conf.config_id = ech_ext.config_id
    - checks that ech_conf.cipher_suite = ech_ext.cipher_suite
    - generates a HPKE context from the private key corresponding to
      ech_conf.public_key and decrypts the payload by generating the client_hello_AAD to retrieve the Client Hello Inner
  If any of these previous steps fails then the frontend rejects the ECH (go to step 4). Otherwise, the frontend accepts the ECH. Finally, it verifies that the encrypted_client_hello of the Client Hello Inner is of type inner (otherwise raise `illegal_parameter`) and forwards to the backend server with the domain corresponding to the SNI of the ClientHelloInner (Go to step 6).
4. When the frontend server rejects the ECH, it should act as a TLS server with the ClientHelloOuter but it must send during the handshake an ECH extension in its
  EncryptedExtensions with a retry configuration.
5. For a standard TLS connexion (or a frontend with rejected ECH), the server checks
that ciphersuite in CH1 is the ciphersuite that he is willing to accept (otherwise raise `handshake_failure`). It also need the KeyShare extension as follows:
    - If KeyShare extension of the client hello is invalid or does not correspond
      to the group accepted by the server, raise `handshake_failure`
    - If the KeyShare extension contains the group accepted by the server +
      a key share then the server proceed with other verifications.
        (Go to step 7 - At that point the current transcript is CH1).
    - If the KeyShare extension only contains the group accepted by the server
      then it must send an HRR (it contains no extension except KeyShare).
    - When receiving the new client hello CH2, the server verifies that the keyshare
      extension contains the correct group + a key share (otherwise raise `handshake_failure`).
      (Go to step 7 - At that point current transcript is CH1 - HRR - CH2 and the server will reject early data)
6. For an ECH connexion, i.e. a connexion where the frontend accepted the ECH
  and forwarded the inner to the backend, the backend checks
  that ciphersuite in Inner1 is the ciphersuite that he is willing to accept (otherwise raise `handshake_failure`). It also need to check the key share extension:
    - If KeyShare extension of the Inner1 is invalid or does not corresponds
      to the group accepted by the backend, raise `handshake_failure`
    - If the KeyShare extnesion contains the group accepted by the server +
      a key share then the server proceed with other verifications.
        (Go to step 7 - At that point the current transcript is Inner1)
    - If the KeyShare extension only contains the group accepted by the server
      then it sends an HRR with a special ECH extension (function generate_hello_retry_request
      in ech_functions.pvl)
    - When the frontend receives the new client hello Outer2, it :
      - Checks that the version of Outer2 if TLS 1.3 and the SNI corresponds to
        its domain (otherwise raise `unexpected_message`)
      - Checks that there is an ECH extension of type Outer (otherwise raise `missing_extension`)
      - Checks that the ciphersuite and config_id of Outer2.ECH are the same as in
        Outer1.ECH, and that Outer2.ECH.enc is empty (otherwise raise `illegal_parameter`)
      - Decrypts the payload by using the context that was generated at step 3
        and by generating the client_hello_AAD (if it fails then raise `decrypt_error`) to retreive to retrieve Inner2
      - Forwards to the backend server that checks the SNI and that Inner2.ECH is of type inner (otherwise raise `illegal_parameter`).
        (Go to step 7 - At that point the current transcript for the backend is
        Inner1 - HRR - Inner2 and the server will reject early data)

7. This step explains how the server analyses the client hello after the HRR verification.
  When we mention the client hello CH in this step, it's the latest client hello received.
  It should be for both standard TLS, or frontend with rejected ECH, or the backend server.
    1. The server checks on CH the following (otherwise `handshake_failure`):
      - The version is TLS 1.3
      - The ciphersuite matches
      - The group matches
    2. The server generates the `early_secret`, retrieves the pre shared key (if any) from CH
       and generates the PSK extension that will be send by the server
      (process `generate_early_secret_psk_extension` in `tls_functions.pvl`)
    3. If CH contains an `early_data` extension with value `EarlyDataIndication` and the server
    accepts early data and the psk retrieved allows early data then
    the server generates the 0-RTT client_write_key `wkc0` (function `kdf_k0` in `key_schedule.pvl`) and waits for a message from the client. Upon receiving it, it tries to decrypts using `wkc0` (otherwise raise `bad_record_mac`).
    4. The servers generates the DH encapsulation from the key share in CH
      and generate the handshake_secret (function `kdf_hs` in `key_schedule.pvl`).
    5. The servers generates ServerHello
      - [For Backend] The random must be generated by `generate_accept_confirmation` in `key_schedule.pvl`.
      - [For normal] The random is really a random.
    6. After outputting the ServerHello, the server generates (function `kdf_ms` of `key_schedule.pvl`):
      - the master_secret,
      - the `chk` client_write_key for handshake record,
      - the `shk` server_write_key for handshake record,
      - the `cfin` client_finished_key
      - the `sfin` server_finished_key
    7. The servers output the content of EncryptedExtension encrypted with `shk`. It will contain:
      - an early_data extension if the server successfuly decrypted the 0-RTT message of step 7.3
      - an ECH extension with the retry config (for a frontend that rejected ECH)
      - the extra extension `ee_extra`
    8. If no psk was provided or the server did not accept the PSK then
      - A request for client certificate encrypted by (shk) is sent if `req_cert = true`
      - The server's certificate is sent encrypted by (shk)
      - The server's CertificateVerify is sent encrypted by (shk)
    9. The server outputs its Finished message encrypted by (shk) that contains
          a hmac of the transcript with the key (sfin)
    10. If the server requested a client certificate at step 7.8
      then:
        - It expects a Certificate from the client encrypted by (chk)
        - It expects a CertificateVerify from the client encrypted by (chk)
        - It verifies that the certificate received is a valid one that that the signature matches the transcript.
    11. If the server accepted early data then it expects an EndOfEarlyData message from the client encrypted with `wkc0`.
    12. The server expects a Finished message from the client encrypted with (chk)
      and checks that the content of the Finished message is a hmac of the transcript
      with the key (cfin)
    13. For the Post Handshake part, the server generates (function `kdf_k` of `key_schedule.pvl`):
      - the `cak` client_write_key for Application Data,
      - the `sak` server_write_key for Application Data,
      - the `cfkad` client finished_key for Application Data
      - the `ems` exporter_master_secret  
    14. The server generates a new ticket_nonce, the resumption_master_secret (function `kdf_psk` of `key_schedule.pvl`) and the new psk (function `psk_from_ticket` of `key_schedule.pvl`). It sends a NewSessionTicket message encrypted with `sak`. This
    message will include the early data extension with EarlyDataIndication if `tck_ED = true`.
    15. Sent application data messages are encrypted with `sak`. Received application data messages are decrypted with `cak`.
    16. If CH contained a `post_handshake_auth` extension then:
      - A request for client certificate encrypted by (sak) is sent with a fresh random `req_rand`
      - The server expects a Certificate from the client encrypted by (cak) that contain a certifiate and the random `req_rand`
      - The server expects a CertificateVerify from the client encrypted by (cak) and verifies that the certificate received is a valid one that that the signature matches the transcript.
      - The server expects a Finished message from the client encrypted with (cak)
        and checks that the content of the Finished message is a hmac of the transcript
        with the key (cfkad). The transcript here does not include the application data message including the NewSessionTicket.

  Steps 7.15 and 7.16 can repeated.
