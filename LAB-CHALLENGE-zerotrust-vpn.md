# 🎯 LAB CHALLENGE — "Trust Nobody": Rebuilding Remote Access After a Breach

**Difficulty:** Advanced · **Est. time:** 8–14 hours · **Platform:** PNetLab / EVE-NG
**Technologies:** Cisco ASA · Cisco ISE · AnyConnect · RADIUS · Certificates · Posture · dACLs · Segmentation

## 📖 The Scenario

**NordWerk Logistik GmbH** — a mid-size logistics company, HQ in Düsseldorf, \~400 employees, plus external contractors who manage the warehouse management software.

**Six weeks ago, they got breached.**

A contractor received a convincing phishing email and handed over his VPN username and password. The attacker connected to the corporate VPN at 02:40 on a Sunday from an IP in another country. Because the old VPN gave *every* authenticated user *full* internal network access, the attacker:

1. Landed on the internal network with the same reach as a full-time employee
2. Scanned the internal ranges and found an unpatched file server
3. Moved laterally to a management subnet and reached network device admin interfaces
4. Was only detected 9 days later, by accident, during a routine log review

The post-incident report was brutal, and it listed four root causes:

|#|Finding|Why it mattered|
|-|-|-|
|1|**Password-only VPN authentication**|One phished credential = full access. No second factor, no device identity.|
|2|**No least privilege**|Every VPN user landed in the same pool with the same access. Contractor = employee = admin.|
|3|**No endpoint health checks**|The contractor's laptop had no AV running and was months behind on patches. Nobody knew.|
|4|**No visibility**|No per-user session logging, no idea who connected, from where, or what they reached.|

**You have been hired to rebuild remote access.** Management's instruction was one sentence:

> \\\\\\\*"Assume the next set of credentials is already stolen. Design it so that still isn't enough."\\\\\\\*

\---

## 🏗️ The Environment You Must Build

```
        VMnet3 — 192.168.71.0/24   ("the internet")
   ┌──────────────┬──────────────┬──────────────┐
   │  EMPLOYEE    │  CONTRACTOR  │   IT-ADMIN   │   ← remote workers
   │  .71.100     │   .71.101    │   .71.102    │
   └──────┬───────┴──────┬───────┴──────┬───────┘
          └──────────────┼──────────────┘
                    ┌────┴────┐  Net cloud
                    │         │
  VMnet1 ───eth1────┤   ASA   ├────eth2─── VMnet2 — 192.168.91.0/24
 192.168.81.0/24    │ Turbo   │            services · ISE .91.10
 PC-management      └────┬────┘            ASA leg  .91.1
 ASDM  .81.10          eth3
                         │  transit 10.10.99.0/24
                  ┌──────┴───────┐
                  │Transit Switch│
                  └──┬────────┬──┘
                ┌────┴───┐ ┌──┴─────┐
                │  CORE  │ │ Core2  │   ← L3, HSRP VIP 10.10.99.254
                └────┬───┘ └───┬────┘      inter-VLAN routing
                     └────┬────┘
              ┌───────────┼───────────┐
           ┌──┴──┐     ┌──┴──┐     ┌──┴──┐
           │Dis5 │     │Dis6 │     │Dis3 │
           └──┬──┘     └──┬──┘     └──┬──┘
           ┌──┴──┐     ┌──┴──┐     ┌──┴──┐
           │ AC8 │     │ AC9 │     │AC10 │
           └──┬──┘     └──┬──┘     └──┬──┘
              │           │           │
      ┌───────┴──────┐ ┌──┴───────┐ ┌─┴──────────────┐
      │Corporate LAN │ │Mgmt Subnet│ │  DMZ / Servers │
      │ 10.10.10.0/24│ │10.10.30/24│ │  172.16.1.0/24 │
      │ VPC14–VPC17  │ │VPC18–VPC21│ │ SRV11 APP  .50 │
      └──────────────┘ │JUMP-HOST  │ │ SRV12 FILE .60 │
                       │      .10  │ │ SRV13 REMED.70 │
                       └───────────┘ └────────────────┘
```

### VMnet mapping (VMware / PNetLab)

|VMnet|Subnet|Purpose|ASA interface|
|-|-|-|-|
|**VMnet3**|192.168.71.0/24|"Internet" — AnyConnect clients dial in|`eth0` outside — .71.10|
|**VMnet1**|192.168.81.0/24|ASDM / management|`eth1` mgmt — .81.10|
|**VMnet2**|192.168.91.0/24|Services segment — **ISE .91.10**|`eth2` services — .91.1|
|—|10.10.99.0/24|Transit: ASA ↔ CORE/Core2|`eth3` inside — 10.10.99.1|

> The ASA does \\\\\\\*\\\\\\\*security policy\\\\\\\*\\\\\\\*; the CORE/Core2 pair does \\\\\\\*\\\\\\\*inter-VLAN routing\\\\\\\*\\\\\\\* for everything internal. That's the production split — a firewall shouldn't be routing every campus VLAN.

### Addressing you must use

|Zone|Subnet|Key hosts|
|-|-|-|
|Outside / "Internet" (VMnet3)|192.168.71.0/24|ASA outside `.10`, clients `.100`–`.102`|
|ASA management (VMnet1)|192.168.81.0/24|ASA mgmt `.10`, PC-management `.100`|
|Services / ISE (VMnet2)|192.168.91.0/24|ASA services `.1`, **ISE `.10`**|
|Transit (ASA ↔ cores)|10.10.99.0/24|ASA `.1`, CORE `.2`, Core2 `.3`, **HSRP VIP `.254`**|
|Corporate LAN|10.10.10.0/24|VPC14–VPC17|
|Management subnet|10.10.30.0/24|VPC18–VPC21, `JUMP-HOST .10`, syslog `.80`|
|DMZ / Server farm|172.16.1.0/24|`APP-SRV .50` (SRV11), `FILE-SRV .60` (SRV12), `REMEDIATION .70` (SRV13)|

> ⚠️ \\\\\\\*\\\\\\\*The cores must have a route back to the VPN pools\\\\\\\*\\\\\\\* (`10.20.0.0/16 → 10.10.99.1`). Without it, VPN clients reach internal hosts but the replies never return — a classic one-way-traffic failure.

### VPN address pools you must create

|Pool|Range|For|
|-|-|-|
|Employee|10.20.10.0/24|full-time staff|
|Contractor|10.20.20.0/24|external contractors|
|Admin|10.20.30.0/24|IT administrators|
|Quarantine|10.20.99.0/24|endpoints failing health checks|

\---

## 🎯 The Requirements (what "done" looks like)

Management signed off on these. Every one must be demonstrably working.

### R1 — Identity is centralized

No user accounts on the ASA itself. **ISE is the single source of identity**, and the ASA is a RADIUS client. If ISE says no, the user does not get in.

### R2 — A stolen password alone must not work

The contractor's phished password must be **insufficient by itself**. Something the attacker cannot phish must also be required.

### R3 — Access depends on *who you are*, not just *that you authenticated*

Three roles, three very different levels of reach:

|Role|Must be able to reach|Must **NOT** be able to reach|
|-|-|-|
|**Employee**|Corporate LAN, `APP-SRV`, `FILE-SRV`, DMZ web|Management subnet, network devices|
|**Contractor**|`APP-SRV` **only** (the WMS application)|Everything else — LAN, file server, mgmt, DMZ|
|**IT-Admin**|Management subnet + `JUMP-HOST`, plus everything above|—|

Access must be enforced **centrally from ISE**, not hard-coded on the ASA. Adding a fourth role later must not require touching the ASA config.

### R4 — Unhealthy endpoints don't get in

Before an endpoint reaches anything, its health must be assessed. A machine that fails (no AV, missing patches) must land in **quarantine** with access to *remediation resources only* — and must be able to get out of quarantine once it's fixed, **without reconnecting**.

### R5 — Visibility

For every session you must be able to answer: **who** connected, **when**, **from where**, **which role they got**, and **whether their endpoint was compliant**. Session accounting must be running.

### R6 — Sensible tunneling

Decide and justify: full tunnel or split tunnel. Whatever you choose, corporate DNS must resolve internal names correctly, and your choice must not create a security hole.

\---

## 🧩 Your Tasks

Work through these in order. Each phase should be **verified before you move on**.

### Phase 0 — Build and baseline

* \[ ] Build the topology in PNetLab with the addressing above
* \[ ] Confirm full internal reachability *before* any VPN work
* \[ ] Confirm remote clients can reach the ASA outside interface
* \[ ] Get ISE deployed, reachable, and its services running

### Phase 1 — Get a basic tunnel up

* \[ ] Stand up AnyConnect remote access on the ASA with **local** authentication
* \[ ] One test user connects and gets an IP from a pool
* \[ ] **This is your baseline** — prove the plumbing works before adding identity

> 💡 Why start with local auth? Same principle as every lab you've built: get one layer working and verified before stacking the next. If ISE integration fails later, you'll know the VPN itself was fine.

### Phase 2 — Move identity to ISE (R1)

* \[ ] Register the ASA in ISE as a network device
* \[ ] Point the ASA's VPN authentication at ISE via RADIUS
* \[ ] Create three identity groups in ISE: `Employees`, `Contractors`, `IT-Admins`
* \[ ] Create one test user in each group
* \[ ] Verify each user can authenticate **and that you can see it in ISE Live Logs**
* \[ ] Remove the local user — prove ISE is now the only path in

### Phase 3 — Role-based access (R3)

* \[ ] Design the access rules for each of the three roles
* \[ ] Enforce them **from ISE**, dynamically, per user
* \[ ] Assign each role its correct address pool
* \[ ] **Prove it:** log in as each role and test reachability against the table in R3 — including the things each role must *not* reach

> 🎯 This is the core of the lab. If a contractor can ping the file server, you have failed the requirement that caused the breach.

\---

*Solutions, full configurations, and answers to all design questions are in the companion solution file. Try each phase before you look.*

