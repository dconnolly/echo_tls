changequote(<!,!>)dnl

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
define(<!PSK!>)dnl
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
