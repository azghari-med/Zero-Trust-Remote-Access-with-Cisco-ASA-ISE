A contractor's phished credential led to a breach: flat VPN access let the
attacker move laterally across the whole network. This lab rebuilds remote
access so the next stolen credential isn't enough.

Cisco ISE is the single identity source. When a user connects via AnyConnect,
the ASA proxies authentication to ISE, and ISE returns a per-role downloadable
ACL that the ASA enforces for that session. A contractor is restricted to a
single application server; an employee reaches the LAN and file servers; an
IT-admin reaches everything — all decided centrally in ISE, with zero
role-specific config on the firewall.

Built on a full campus: dual core switches with HSRP, distribution and access
layers, VLAN segmentation, and a transit link to the ASA.

Stack: Cisco ASA · Cisco ISE · AnyConnect · RADIUS · downloadable ACLs · HSRP