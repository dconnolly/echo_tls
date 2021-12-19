dnl
Detailed scenario verified:
ifdef(<!HRR!>,<!dnl
  - The attacker chooses if clients send their DH key share with the DH group
  - Servers send Hello Retry Request if clients do not send their DH key share.
!>,<!dnl
  - Clients send their DH key share with the DH group
  - Servers do not send Hello Retry Request and abort instead.
!>)dnl
dnl
dnl
ifdef(<!Ticket!>,<!dnl
  - At the end of each handshake, the server generates a new ticket
  - Clients can reused the PSK obtained from a ticket.
!>,<!dnl
  - Server never generates tickets
  - Clients are not expecting to receive a ticket.
!>)dnl
dnl
dnl
ifdef(<!PHData!>,<!dnl
  - Clients and Servers can send/receive Post Handshake Data
!>,<!dnl
  - Clients and Servers do not send nor expect Post Handshake Data
!>)dnl
dnl
dnl
ifdef(<!PHAuth!>,<!dnl
  - Servers can request Post Handshake Authentication
!>,<!dnl
  - Servers do not request Post Handshake Authentication and clients are not expecting it
!>)dnl
dnl
dnl
ifdef(<!EarlyData!>,<!dnl
  - Clients and Servers can send/receive 0-RTT early data
!>,<!dnl
  - Clients and Servers do not send nor expect 0-RTT early data
!>)dnl
dnl
dnl
  - Private keys of ECH configurations ifdef(<!CompEch!>,<!can!>,<!cannot!>) be compromised.
  - PSKs obtained from tickets ifdef(<!CompTicket!>,<!can!>,<!cannot!>) be compromised.
  - External PSKs ifdef(<!CompExtPSK!>,<!can!>,<!cannot!>) be compromised.
  - Long term keys of certificates ifdef(<!CompLgt!>,<!can!>,<!cannot!>) be compromised.
dnl
dnl
ifdef(<!MultCS!>,<!dnl
  - The ciphersuites and DH groups are choosen by the attacker.
!>,<!dnl
  - The ciphersuites and DH groups are not choosen by the attacker. They are the same for all TLS handshake.
    The ciphersuites and groups in ECH configurations differs from the ones used in the TLS handshake.
!>)dnl
dnl
dnl
  - The ciphersuites and DH groups offered/choosen by honest clients/servers ifdef(<!WeakCS!>,<!can!>,<!cannot!>) be weak.
dnl
dnl
ifdef(<!SetPsk!>,<!dnl
ifdef(<!DefaultPsk!>,<!dnl
  - The clients/servers always offer/accept PSK (if checks are ok)
!>,<!dnl
  - The clients/servers never offer/accepts PSK
!>)dnl
!>,<!dnl
  - The attacker chooses if a client/server offers/accepts a PSK (even if checks are ok)
!>)dnl
dnl
dnl
ifdef(<!SetGrease!>,<!dnl
ifdef(<!DefaultGrease!>,<!dnl
  - ECH clients always uses grease
!>,<!dnl
  - ECH clients never uses grease
!>)dnl
!>,<!dnl
  - The attacker chooses if a client uses grease
!>)dnl
dnl
dnl
ifdef(<!SetCert!>,<!dnl
ifdef(<!DefaultCert!>,<!dnl
  - Server always request client authentication
!>,<!dnl
  - Sever never request client authentication
!>)dnl
!>,<!dnl
  - The attacker chooses if a server request client authentication
!>)dnl
dnl
dnl
ifdef(<!SetUseEch!>,<!dnl
ifdef(<!DefaultUseEch!>,<!dnl
  - All servers use ECH
!>,<!dnl
  - No server uses ECH
!>)dnl
!>,<!dnl
  - The attacker chooses if a server uses ECH
!>)dnl
dnl
dnl
ifdef(<!ClientsTLS!>,<!dnl
ifdef(<!ClientsEch!>,<!dnl
  - Both ECH and TLS clients
!>,<!dnl
  - Only TLS clients
!>)dnl
!>,<!dnl
ifdef(<!ClientsEch!>,<!dnl
  - Only ECH clients
!>,<!dnl
  - BUG !! No client at all.... a mistake must have occured...
!>)dnl
!>)dnl
dnl
dnl


(********************************************************)
(* Equivalence scenario                                 *)
(********************************************************)
dnl Scenarios considered:
dnl  All scenario can be done with HRR activated or deactivated. Deactivating the
dnl  HRR speedup the verification time. The first 3 scenarios are the fastest.
dnl  Scenarios 4,5 and 5 can take a very long time to be verified.
dnl Scenario 1
ifdef(<!SCENARIO1!>,<!dnl
ifdef(<!NOHRR!>,<!dnl
	(* Scenario 1 with no HRR : *)
  (*  - Clients send their DH key share with the DH group *)
  (*  - Servers do not send Hello Retry Request and abort instead. *)
define(<!KEX!>)dnl
!>,<!dnl
	(* Scenario 1 with HRR : *)
  (*  - The attacker chooses if clients send their DH key share with the DH group *)
  (*  - Servers send Hello Retry Request if clients do not send their DH key share. *)
define(<!UKEX!>)dnl
!>)dnl
  (*  - Clients send a PSK *)
  (*  - Clients do no use GREASE *)
  (*  - Servers do not request client certificate *)
	(*  - ECH config keys of client-facing servers are not compromised *)
	(*  - The attacker can choose to compromise a PSK *)
	(*  - The attacker can choose to compromise a certificate *)
define(<!DOPSK!>)dnl
define(<!NOGREASE!>)dnl
define(<!NOCERT!>)dnl
!>)dnl
dnl
dnl Scenario 2
ifdef(<!SCENARIO2!>,<!dnl
ifdef(<!NOHRR!>,<!dnl
	(* Scenario 2 with no HRR : *)
  (*  - Clients send their DH key share with the DH group *)
  (*  - Servers do not send Hello Retry Request and abort instead. *)
define(<!KEX!>)dnl
!>,<!dnl
	(* Scenario 2 with HRR : *)
  (*  - The attacker chooses if clients send their DH key share with the DH group *)
  (*  - Servers send Hello Retry Request if clients do not send their DH key share. *)
define(<!UKEX!>)dnl
!>)dnl
	(*  - Clients do not send a PSK *)
  (*  - Clients do no use GREASE *)
  (*  - Servers do not request client certificate *)
	(*  - ECH config keys of client-facing servers are not compromised *)
	(*  - The attacker can choose to compromise a PSK *)
	(*  - The attacker can choose to compromise a certificate *)
define(<!NOPSK!>)dnl
define(<!NOGREASE!>)dnl
define(<!NOCERT!>)dnl
!>)dnl
dnl
dnl Scenario 3
ifdef(<!SCENARIO3!>,<!dnl
ifdef(<!NOHRR!>,<!dnl
	(* Scenario 3 with no HRR : *)
  (*  - Clients send their DH key share with the DH group *)
  (*  - Servers do not send Hello Retry Request and abort instead. *)
define(<!KEX!>)dnl
!>,<!dnl
	(* Scenario 3 with HRR : *)
  (*  - The attacker chooses if clients send their DH key share with the DH group *)
  (*  - Servers send Hello Retry Request if clients do not send their DH key share. *)
define(<!UKEX!>)dnl
!>)dnl
	(*  - Clients do not send a PSK *)
	(*  - Clients do no use GREASE *)
	(*  - Servers request client certificate *)
	(*  - ECH config keys of client-facing servers are not compromised *)
	(*  - The attacker can choose to compromise a PSK *)
	(*  - The attacker can choose to compromise a certificate *)
define(<!NOPSK!>)dnl
define(<!NOGREASE!>)dnl
define(<!CERT!>)dnl
!>)dnl
dnl
dnl Scenario 4
ifdef(<!SCENARIO4!>,<!dnl
ifdef(<!NOHRR!>,<!dnl
	(* Scenario 4 with no HRR : *)
  (*  - Clients send their DH key share with the DH group *)
  (*  - Servers do not send Hello Retry Request and abort instead. *)
define(<!KEX!>)dnl
!>,<!dnl
	(* Scenario 4 with HRR : *)
  (*  - The attacker chooses if clients send their DH key share with the DH group *)
  (*  - Servers send Hello Retry Request if clients do not send their DH key share. *)
define(<!UKEX!>)dnl
!>)dnl
	(*  - The attacker chooses if clients send a PSK *)
	(*  - Clients do no use GREASE *)
	(*  - The attacker chooses if servers request client certificate *)
	(*  - ECH config keys of client-facing servers are not compromised *)
	(*  - The attacker can choose to compromise a PSK *)
	(*  - The attacker can choose to compromise a certificate *)
define(<!UPSK!>)dnl
define(<!NOGREASE!>)dnl
define(<!UCERT!>)dnl
!>)dnl
dnl
dnl Scenario 5
ifdef(<!SCENARIO5!>,<!dnl
ifdef(<!NOHRR!>,<!dnl
	(* Scenario 5 with no HRR : *)
  (*  - Clients send their DH key share with the DH group *)
  (*  - Servers do not send Hello Retry Request and abort instead. *)
define(<!KEX!>)dnl
!>,<!dnl
	(* Scenario 5 with HRR : *)
  (*  - The attacker chooses if clients send their DH key share with the DH group *)
  (*  - Servers send Hello Retry Request if clients do not send their DH key share. *)
define(<!UKEX!>)dnl
!>)dnl
	(*  - The attacker chooses if clients send a PSK *)
	(*  - The attacker chooses if clients use GREASE *)
	(*  - The attacker chooses if servers request client certificate *)
	(*  - ECH config keys of client-facing servers are not compromised *)
	(*  - The attacker can choose to compromise a PSK *)
	(*  - The attacker can choose to compromise a certificate *)
define(<!UPSK!>)dnl
define(<!UGREASE!>)dnl
define(<!UCERT!>)dnl
!>)dnl
dnl
dnl Scenario 6
ifdef(<!SCENARIO6!>,<!
ifdef(<!NOHRR!>,<!dnl
	(* Scenario 6 with no HRR : *)
  (*  - Clients send their DH key share with the DH group *)
  (*  - Servers do not send Hello Retry Request and abort instead. *)
define(<!KEX!>)dnl
!>,<!dnl
	(* Scenario 6 with HRR : *)
  (*  - The attacker chooses if clients send their DH key share with the DH group *)
  (*  - Servers send Hello Retry Request if clients do not send their DH key share. *)
define(<!UKEX!>)dnl
!>)dnl
	(*  - The attacker chooses if clients send a PSK *)
	(*  - The attacker chooses if clients use GREASE *)
	(*  - The attacker chooses if servers request client certificate *)
	(*  - The attacker can choose to compromise an ECH config key of a client-facing server *)
	(*  - The attacker can choose to compromise a PSK *)
	(*  - The attacker can choose to compromise a certificate *)
define(<!UPSK!>)dnl
define(<!UGREASE!>)dnl
define(<!UCERT!>)dnl
define(<!DISECH!>)dnl
!>)dnl
