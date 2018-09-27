---
title: Constrained Join Proxy for Bootstrapping Protocols
abbrev: Join-Proxy
docname: draft-ietf-vanderstok-constrained-join-proxy-00

# stand_alone: true

ipr: trust200902
area: Internet
wg: anima Working Group
kw: Internet-Draft
cat: std

coding: us-ascii
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:


- ins: M. Richardson
  name: Michael Richardson
  org: Sandelman Software Works
  email: mcr+ietf@sandelman.ca

- ins: P. van der Stok
  name: Peter van der Stok
  org: vanderstok consultancy
  email: consultancy@vanderstok.org

- ins: P. Kampanakis
  name: Panos Kampanakis
  org: Cisco Systems
  email: pkampana@cisco.com

normative:
  RFC2119:
  RFC6347:
  RFC7049:
  RFC7250:
  RFC7950:
  RFC5652:
  RFC8152:
  RFC8366:
  I-D.ietf-anima-bootstrapping-keyinfra:
  I-D.ietf-core-object-security:
  I-D.ietf-ace-cbor-web-token:
  I-D.ietf-ace-coap-est:
  ieee802-1AR:
    target: "http://standards.ieee.org/findstds/standard/802.1AR-2009.html"
    title: "IEEE 802.1AR Secure Device Identifier"
    author:
      ins: "IEEE Standard"
    date: 2009

informative:
  pledge:
    title: "Dictionary.com Unabridged"
    target: "http://dictionary.reference.com/browse/pledge"
    author:
      -
        name: Dictionary.com
    date: 2015

  duckling:
    title: "The resurrecting duckling: security issues for ad-hoc wireless networks"
    target: "https://www.cl.cam.ac.uk/~fms27/papers/1999-StajanoAnd-duckling.pdf"
    author:
      -
        ins: F. Stajano
        name: Frank Stajano
      -
        ins: R. Anderson
        name: Ross Anderson
    date: 1999
  RFC6690:
  RFC7030:
  RFC7228:
  I-D.kumar-dice-dtls-relay:
  RFC4944:
  RFC7252:
  RFC6775:

--- abstract

This document defines a protocol to securely assign a pledge to an
owner, using an intermediary node between pledge and owner.  This intermediary node is known as a "constrained-join-proxy".

This document extends the work of {{I-D.ietf-anima-bootstrapping-keyinfra}} by replacing the Circuit-proxy by a stateless constrained join-proxy, that uses IP encapsulation.


--- middle

# Introduction

Enrolment of new nodes into constrained networks with constrained nodes
present is described in
{{I-D.ietf-anima-bootstrapping-keyinfra}} and makes use of Enrolment over Secure Transport (EST) <xref target= "RFC7030"/>. The specified solutions use https and may be too large in terms of
code space or bandwidth required. Constrained devices in constrained networks {{RFC7228}} typically implement the IPv6 over Low-Power Wireless personal Area Networks (6LoWPAN) {{RFC4944}} and Constrained Application Protocol (CoAP) {{RFC7252}}.  

CoAP has chosen Datagram Transport Layer Security (DTLS) {{RFC6347}} as
the preferred security protocol for authenticity and confidentiality
of the messages. A constrained version of EST, using Coap and DTLS, is described in <xref target="I-D.ietf-ace-coap-est"/>. 

DTLS is a client-server protocol relying on the underlying IP layer
to perform the routing between the DTLS Client and the DTLS Server.
However, the new "joining" device will not
be IP routable until it is authenticated to the network.  A
new "joining" device can only initially use a link-local IPv6 address
to communicate with a neighbour node using neighbour discovery
{{RFC6775}} until it receives the necessary network configuration
parameters.  However, before the device can receive these
configuration parameters, it needs to authenticate itself to the network to which it connects. In {{I-D.ietf-anima-bootstrapping-keyinfra}} Enrolment over Secure Transport (EST) {{RFC7030}} is used to authenticate the joining device. However, IPv6 routing is necessary to establish a connection between joining device and the EST server.

This document specifies a Join-proxy and protocol to act as intermediary between joining device and EST server to establish a connection between joining device and EST server.

This document is very much inspired by text published earlier in {{I-D.kumar-dice-dtls-relay}}.

# Terminology          {#Terminology}

The following terms are defined in {{RFC8366}}, and are used
identically as in that document: artifact, imprint, domain, Join
Registrar/Coordinator (JRC), Manufacturer Authorized Signing Authority
(MASA), pledge, Trust of First Use (TOFU), and Voucher.

# Requirements Language {#rfc2119}

In this document, the key words "MUST", "MUST NOT", "REQUIRED",
"SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY",
and "OPTIONAL" are to be interpreted as described in BCP 14, RFC 2119
{{RFC2119}} and indicate requirement levels for compliant STuPiD
implementations.

# Join Proxy functionality

As depicted in the {{fig-net}}, the joining Device, or pledge (P), is more than one
hop away from the EST server (E) and not yet authenticated into the
network.  At this stage, it can only communicate one-hop to its
nearest neighbour, the Join proxy (J) using their link-local IPv6 addresses.
However, the Device needs to communicate with end-to-end security
with a Registrar hosting the EST server (E) to authenticate and get
the relevant system/network parameters.  If the Pledge (P) initiates
a DTLS connection to the EST server whose IP address has been
pre-configured, then the packets are dropped at the Join Proxy (J)
since the Pledge (P) is not yet admitted to the network or there is
no IP routability to Pledge (P) for any returned messages.

~~~~
                              
                      ++++    
                      |E |----       +--+        +--+
                      |  |    \      |J |........|P |
                      ++++     \-----|  |        |  |
                   EST server        +--+        +--+
                   REgistrar       Join Proxy   PLedge
                                                "Joining" Device

~~~~
{: #fig-net title='multi-hop enrolment.' align="left"}

Furthermore, the Pledge (P) may wish to establish a secure connection
to the EST server (E) in the network assuming appropriate credentials
are exchanged out-of-band, e.g. a hash of the Pledge (P)'s raw public
key could be provided to the EST server (E).  However, the Pledge (P)
is unaware of the IP address of the EST-server (E) to initiate a DTLS
connection and perform authentication with.

An DTLS connection is required between Pledge and EST server. To overcome the problems with non-routability of DTLS packets and/
or discovery of the destination address of the EST Server to
contact, the Join Proxy is introduced.  This Join-Proxy functionality is
configured into all authenticated devices in the network which may
act as the Join Proxy (J) for newly joining nodes.  The Join Proxy allows for routing of the packets from the Pledge (P) using
IP routing to the intended EST Server.  

# Join Proxy specification

In this section, the constrained Join Proxy functionality is specified using DTLS and coaps.  When a joining device as a client attempts a DTLS
connection to the EST server, it uses its link-
local IP address as its IP source address.  This message is
transmitted one-hop to a neighbour node.  Under normal circumstances,
this message would be dropped at the neighbour node since the joining
device is not yet IP routable or it is not yet authenticated to send
messages through the network.  However, if the neighbour device has
the Join Proxy functionality enabled, it routes the DTLS message to a
specific EST Server.  Additional security mechanisms need to exist
to prevent this routing functionality being used by rogue nodes to
bypass any network authentication procedures.

The Join-proxy is stateless to minimize the requirements on the constrained Join-proxy device.

If an untrusted DTLS Client that can only use link-local addressing wants to contact
 a trusted end-point EST Server, it sends the DTLS message to the Join Proxy. The Join Proxy encapsulates this message into a new type of
   message called Join ProxY (JPY) message.  The JPY message consists of
   two parts:

  * Header (H) field: consisting of the source link-local address and port of the DTLS Client device, and
  * Contents (C) field: containing the original DTLS message.

 On receiving the JPY message, the EST Server decapsulates it to
 retrieve the two parts.  It uses the Header field information to transiently store the DTLS Client's address and port.  The EST
 Server then performs the normal DTLS operations on the DTLS message
 from the Contents field.  However, when the EST Server replies, it
 also encapsulates its DTLS message in a JPY message back to the Join Proxy.  The Header contains the original source link-local address
 and port of the DTLS Client from the transient state stored earlier
 (which can now be discarded) and the Contents field contains the DTLS
 message.

On receiving the JPY message, the Join Proxy decapsulates it to
retrieve the two parts.  It uses the Header field to route the DTLS
message retrieved from the Contents field to the joining node.

The {{fig-join}} depicts the message flow diagram when the EST
Server end-point address is known only to the Join Proxy:

~~~~

+--------------+------------+---------------+-----------------------+
| EST  Client  | Join Proxy |    EST server |        Message        |
|     (P)      |     (J)    |      (E)      |Src_IP:port|Dst_IP:port|
+--------------+------------+---------------+-----------+-----------+
|      --ClientHello-->                     | IP_C:p_C  |IP_Ra:5684 |
|                    --JPY[H(IP_C:p_C),-->  | IP_Rb:p_Rb|IP_S:5684  |
|                          C(ClientHello)]  |           |           |
|                    <--JPY[H(IP_C:p_C),--  | IP_S:5684 |IP_Rb:p_Rb |
|                         C(ServerHello)]   |           |           |
|      <--ServerHello--                     | IP_Ra:5684|IP_C:p_C   |
|              :                            |           |           |
|              :                            |     :     |    :      |
|                                           |     :     |    :      |
|      --Finished-->                        | IP_C:p_C  |IP_Ra:5684 |
|                    --JPY[H(IP_C:p_C),-->  | IP_Rb:p_Rb|IP_S:5684  |
|                          C(Finished)]     |           |           |
|                    <--JPY[H(IP_C:p_C),--  | IP_S:5684 |IP_Rb:p_Rb |
|                         C(Finished)]      |           |           |
|      <--Finished--                        | IP_Ra:5684|IP_C:p_C   |
|              :                            |     :     |    :      |
+-------------------------------------------+-----------+-----------+
IP_C:p_C = Link-local IP address and port of DTLS Client
IP_S:5684 = IP address and coaps port of DTLS Server
IP_Ra:5684 = Link-local IP address and coaps port of DTLS Relay
IP_Rb:p_Rb = IP address(can be same as IP_Ra) and port of DTLS Relay

JPY[H(),C()] = Join Proxy message with header H and content C

~~~~
{: #fig-join title='constrained joining message flow.' align="left"}

# Design Considerations

TBD

# Security Considerations

TBD.

# IANA Considerations


# Acknowledgements

Much of this text is inspired by {{I-D.kumar-dice-dtls-relay}}.

# Changelog

empty

--- back
