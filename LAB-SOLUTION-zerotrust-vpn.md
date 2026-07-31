# 🔑 SOLUTION — "Trust Nobody": Rebuilding Remote Access After a Breach

**Companion to:** `LAB-CHALLENGE-zerotrust-vpn.md`
**Contains:** full configurations, injection diagnoses, and answers to all design questions.

> Configs are written for ASA 9.x + ISE 2.x/3.x. Command syntax varies slightly by version — where it matters, it's flagged. Adjust interface names and image filenames to your own gear.

**VMnet / segment mapping used throughout:**

|Segment|Subnet|Role|ASA interface|
|-|-|-|-|
|VMnet3|192.168.71.0/24|"Internet" / AnyConnect clients|`eth0` outside — 192.168.71.10|
|VMnet1|192.168.81.0/24|ASDM management|`eth1` mgmt — 192.168.81.10|
|VMnet2|192.168.91.0/24|Services — **ISE 192.168.91.10**|`eth2` services — 192.168.91.1|
|Transit|10.10.99.0/24|ASA ↔ CORE/Core2 (HSRP VIP .254)|`eth3` inside — 10.10.99.1|
|Corporate LAN|10.10.10.0/24|VPC14–17|*behind the cores*|
|Mgmt subnet|10.10.30.0/24|VPC18–21, JUMP-HOST .10|*behind the cores*|
|DMZ / servers|172.16.1.0/24|APP-SRV .50, FILE-SRV .60, REMEDIATION .70|*behind the cores*|
|VPN pools|10.20.0.0/16|employee / contractor / admin / quarantine|assigned by ISE|

> \\\\\\\*\\\\\\\*Interface naming:\\\\\\\*\\\\\\\* PNetLab shows `eth0`–`eth3`; the ASA CLI may call them `GigabitEthernet0/0`–`0/3` or `Management0/0` + `GigabitEthernet0/0`+. Run `show interface ip brief` and map them to what you see before pasting.

\---

## Phase 0–1 — Base ASA and a Working Baseline Tunnel

Get plumbing working with **local** auth first. Never debug identity and transport at the same time.

### Campus side first — the cores must know about the VPN pools

The ASA can route *into* the campus, but the campus must be able to route *back* to VPN clients. Configure this on **CORE and Core2** before you test anything.

```cisco
! ===== CORE (and mirror on Core2) =====
interface Vlan99
 description TRANSIT-TO-ASA
 ip address 10.10.99.2 255.255.255.0        ! Core2 uses .3
 standby 99 ip 10.10.99.254                  ! HSRP VIP the ASA points at
 standby 99 priority 110                     ! Core2: 100
 standby 99 preempt
!
! Return path for every VPN pool
ip route 10.20.0.0 255.255.0.0 10.10.99.1
!
! Campus SVIs (inter-VLAN routing lives HERE, not on the ASA)
interface Vlan10
 description CORPORATE-LAN
 ip address 10.10.10.2 255.255.255.0
 standby 10 ip 10.10.10.1
interface Vlan30
 description MGMT-SUBNET
 ip address 10.10.30.2 255.255.255.0
 standby 30 ip 10.10.30.1
interface Vlan100
 description DMZ-SERVERS
 ip address 172.16.1.2 255.255.255.0
 standby 100 ip 172.16.1.1
!
! Default route out to the ASA
ip route 0.0.0.0 0.0.0.0 10.10.99.1
```

> ⚠️ \\\\\\\*\\\\\\\*`ip route 10.20.0.0 255.255.0.0 10.10.99.1` is the line everyone forgets.\\\\\\\*\\\\\\\* Without it the VPN client's packets arrive at the server, the server replies, and the reply goes to the campus default gateway instead of back to the ASA — traffic works in exactly one direction and looks like a firewall problem. This is Injection 1.

```cisco
hostname ASA-VPN
!
! ===== eth0 / VMnet3 — the "internet" where AnyConnect clients live =====
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 192.168.71.10 255.255.255.0
 no shutdown
!
! ===== eth1 / VMnet1 — dedicated ASDM management =====
interface GigabitEthernet0/1
 nameif mgmt
 security-level 100
 ip address 192.168.81.10 255.255.255.0
 management-only
 no shutdown
!
! ===== eth2 / VMnet2 — services segment where ISE lives =====
interface GigabitEthernet0/2
 nameif services
 security-level 90
 ip address 192.168.91.1 255.255.255.0
 no shutdown
!
! ===== eth3 — transit link to the campus cores =====
interface GigabitEthernet0/3
 nameif inside
 security-level 100
 ip address 10.10.99.1 255.255.255.0
 no shutdown
!
! ===== Routing =====
! Everything internal (LAN, mgmt subnet, DMZ) sits behind CORE/Core2.
! Point at the HSRP VIP on the transit VLAN — one route covers the campus.
route inside 10.10.0.0 255.255.0.0 10.10.99.254 1
route inside 172.16.1.0 255.255.255.0 10.10.99.254 1
!
! ===== ASDM / management access (VMnet1) =====
http server enable
http 192.168.81.0 255.255.255.0 mgmt
asdm image disk0:/asdm-openjre-7181.bin
ssh 192.168.81.0 255.255.255.0 mgmt
ssh version 2
!
! ===== VPN address pools (one per role) =====
ip local pool EMPLOYEE-POOL   10.20.10.10-10.20.10.250  mask 255.255.255.0
ip local pool CONTRACTOR-POOL 10.20.20.10-10.20.20.250  mask 255.255.255.0
ip local pool ADMIN-POOL      10.20.30.10-10.20.30.250  mask 255.255.255.0
ip local pool QUARANTINE-POOL 10.20.99.10-10.20.99.250  mask 255.255.255.0
!
! ===== NAT exemption — VPN traffic must NOT be NATted =====
object network VPN-POOLS
 subnet 10.20.0.0 255.255.0.0
object network INTERNAL
 subnet 10.10.0.0 255.255.0.0
object network DMZ-NET
 subnet 172.16.1.0 255.255.255.0
object network ISE-NET
 subnet 192.168.91.0 255.255.255.0
!
! DMZ/servers are reached via the inside interface (behind the cores),
! so both INTERNAL and DMZ-NET are exempted on the inside interface.
nat (inside,outside)   source static INTERNAL INTERNAL destination static VPN-POOLS VPN-POOLS no-proxy-arp route-lookup
nat (inside,outside)   source static DMZ-NET  DMZ-NET  destination static VPN-POOLS VPN-POOLS no-proxy-arp route-lookup
nat (services,outside) source static ISE-NET  ISE-NET  destination static VPN-POOLS VPN-POOLS no-proxy-arp route-lookup
!
! ===== AnyConnect =====
webvpn
 enable outside
 anyconnect image disk0:/anyconnect-win-4.10.07061-webdeploy-k9.pkg 1
 anyconnect enable
 tunnel-group-list enable
!
group-policy GP-BASE internal
group-policy GP-BASE attributes
 vpn-tunnel-protocol ssl-client
 dns-server value 172.16.1.10
 default-domain value nordwerk.local
!
! Temporary local user — DELETED in Phase 2
username baseline-test password Lab-Test-2026! privilege 0
username baseline-test attributes
 service-type remote-access
!
tunnel-group NORDWERK-VPN type remote-access
tunnel-group NORDWERK-VPN general-attributes
 address-pool EMPLOYEE-POOL
 default-group-policy GP-BASE
tunnel-group NORDWERK-VPN webvpn-attributes
 group-alias NordWerk enable
```

**Verify:** connect with `baseline-test`, confirm you get a `10.20.10.x` address and can reach `172.16.1.50`.

```cisco
show vpn-sessiondb anyconnect
```

\---

## Phase 2 — ISE Becomes the Identity Source (R1)

### ASA side

```cisco
aaa-server ISE protocol radius
 interim-accounting-update periodic 24
 dynamic-authorization                     ! REQUIRED for CoA (posture, Phase 5)
!
aaa-server ISE (services) host 192.168.91.10
 key NordWerk-RAD-2026
 authentication-port 1812
 accounting-port 1813
!
tunnel-group NORDWERK-VPN general-attributes
 authentication-server-group ISE
 accounting-server-group ISE               ! REQUIRED — CoA needs an accounting session
 no authentication-server-group LOCAL
!
! Prove ISE is the only path in:
no username baseline-test
```

> ⚠️ \\\\\\\*\\\\\\\*`dynamic-authorization` + accounting are not optional.\\\\\\\*\\\\\\\* Without them ISE cannot send a Change of Authorization, and Phase 5's "move out of quarantine without reconnecting" is impossible. This is the single most-missed command in this build.

### ISE side

1. **Administration → Network Resources → Network Devices → Add**

   * Name `ASA-VPN`, IP `192.168.91.1` (the ASA's **services** interface — the source of its RADIUS packets)
   * RADIUS shared secret: `NordWerk-RAD-2026`
   * Enable **CoA** (default port 1700, some deployments use 3799)
2. **Administration → Identity Management → Groups** — create:
`Employees`, `Contractors`, `IT-Admins`
3. **Identities → Users** — create one user per group:
`e.mueller` → Employees · `c.external` → Contractors · `a.admin` → IT-Admins
4. **Policy → Policy Sets** — create a policy set matched on the ASA:

   * Condition: `DEVICE:Device Type EQUALS VPN` (or `Radius:NAS-IP-Address EQUALS 10.10.10.1`)
   * Allowed protocols: `Default Network Access`

**Verify:** each user authenticates; **Operations → RADIUS → Live Logs** shows a green Pass.

\---

## Phase 3 — Role-Based Access Enforced from ISE (R3)

### The authorization matrix (build this first)

|Source role|Corp LAN 10.10.10|APP-SRV .20.50|FILE-SRV .20.60|Mgmt 10.10.30|DMZ 172.16.1|
|-|-|-|-|-|-|
|Employee|permit|permit|permit|**deny**|permit|
|Contractor|**deny**|permit (tcp 443/1433)|**deny**|**deny**|**deny**|
|IT-Admin|permit|permit|permit|permit|permit|

### ISE — Downloadable ACLs

**Policy → Policy Elements → Results → Authorization → Downloadable ACLs**

`DACL-EMPLOYEE`

```
permit ip any 10.10.10.0 255.255.255.0
permit ip any host 172.16.1.50
permit ip any host 172.16.1.60
permit ip any 172.16.1.0 255.255.255.0
deny   ip any 10.10.30.0 255.255.255.0
deny   ip any any
```

`DACL-CONTRACTOR`

```
permit tcp any host 172.16.1.50 eq 443
permit tcp any host 172.16.1.50 eq 1433
deny   ip any any
```

`DACL-ITADMIN`

```
permit ip any 10.10.0.0 255.255.0.0
permit ip any 172.16.1.0 255.255.255.0
deny   ip any any
```

> \\\\\\\*\\\\\\\*Write the explicit `deny ip any any` even though it's implicit.\\\\\\\*\\\\\\\* It makes intent auditable and, on some platforms, avoids surprises with how the implicit rule interacts with the interface ACL.

### ISE — Authorization Profiles

**Policy → Policy Elements → Results → Authorization → Authorization Profiles**

|Profile|DACL|Advanced Attributes|
|-|-|-|
|`AUTHZ-EMPLOYEE`|`DACL-EMPLOYEE`|`Cisco:cisco-av-pair = ip:addr-pool=EMPLOYEE-POOL`|
|`AUTHZ-CONTRACTOR`|`DACL-CONTRACTOR`|`Cisco:cisco-av-pair = ip:addr-pool=CONTRACTOR-POOL`|
|`AUTHZ-ITADMIN`|`DACL-ITADMIN`|`Cisco:cisco-av-pair = ip:addr-pool=ADMIN-POOL`|

> Alternative pool method: return `Class = OU=GP-EMPLOYEE;` to bind an ASA group-policy. That works too, but it requires a matching `group-policy` on the ASA — which weakens the "no ASA changes for a new role" requirement. The `ip:addr-pool` AV-pair only needs the \\\\\\\*pool\\\\\\\* to pre-exist.

### ISE — Authorization Rules

**Policy → Policy Sets → \[your VPN set] → Authorization Policy**

|Order|Rule name|Condition|Result|
|-|-|-|-|
|1|IT-Admin Access|`IdentityGroup:Name EQUALS IT-Admins`|`AUTHZ-ITADMIN`|
|2|Contractor Access|`IdentityGroup:Name EQUALS Contractors`|`AUTHZ-CONTRACTOR`|
|3|Employee Access|`IdentityGroup:Name EQUALS Employees`|`AUTHZ-EMPLOYEE`|
|4|Default|—|`DenyAccess`|

> \\\\\\\*\\\\\\\*Rule order is first-match.\\\\\\\*\\\\\\\* Put the most specific/most privileged rules where they cannot be shadowed by a broader rule above them. This is the cause of Injection 2.

### ASA side — nothing role-specific

The only ASA requirement is that the pools exist. Understand this line:

```cisco
! Default behaviour: VPN traffic BYPASSES interface ACLs
sysopt connection permit-vpn
```

With `sysopt connection permit-vpn` on (default), the **dACL is your enforcement point** — which is exactly what you want, because it's per-user and comes from ISE. If you turn it off, you also have to maintain an interface ACL, and you've re-created the static problem.

**Verify — test the denies, not just the permits:**

```cisco
show vpn-sessiondb detail anyconnect filter name c.external
! confirm the applied dACL name appears in the output
```

From the contractor client: `APP-SRV:443` succeeds, `FILE-SRV` fails, `JUMP-HOST` fails.

\---

## 🎓 What This Lab Actually Teaches

1. **Authentication is not authorization.** Getting in and being allowed to do something are separate decisions, and the second one is where least privilege lives.
2. **Policy belongs in one place.** Enforcement is distributed; policy should not be.
3. **Health is part of identity.** *Who you are* and *what state your device is in* together determine access.
4. **Test the denies.** Anyone can demonstrate that access works. Demonstrating that it is correctly blocked is the actual deliverable.
5. **Know what your controls don't cover.** Network segmentation contains ordinary users well and privileged users barely at all — being able to say so precisely is what separates an engineer from a checklist.

