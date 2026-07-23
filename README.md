# Entra ID Hardening and Privileged Identity Management Lab

Took a deliberately over-permissioned Microsoft Entra tenant from three standing Global Administrators and zero access controls to a just-in-time privileged access model with Conditional Access enforcement, recurring role recertification, and MITRE-mapped identity detections.

**Stack:** Microsoft Entra ID P2, Conditional Access, Identity Protection, Privileged Identity Management, Access Reviews, Azure Log Analytics, KQL

---

## Why I built this

Identity is where most intrusions actually land. I work incidents daily in Microsoft Sentinel, but my privileged access management exposure was conceptual: I could describe just-in-time elevation without having configured it. This lab closes that gap and connects it back to detection work, since the controls and the telemetry they produce are two halves of the same problem.

The build follows a before/after structure. I stood up an insecure tenant on purpose, measured it, hardened it, then measured again.

---

## Environment

| Component | Detail |
|---|---|
| Tenant | Cloud-only Entra tenant, 8 member users, 4 security groups |
| Licensing | Entra ID P2 (31-day trial, 25 seats) |
| Mock org | IT admin, helpdesk, finance, executive, general staff |
| Log destination | Azure Log Analytics workspace, East US |

Roles were assigned against a documented roster of intended access, which is what I graded the remediation against later.

---

## Phase 1: Baseline

Built the insecure starting state and captured it before touching anything.

- Three permanent Global Administrator assignments, including a helpdesk account that had no business holding directory-wide privilege
- No MFA enforcement, Security Defaults disabled
- Zero Conditional Access policies
- Legacy authentication protocols unrestricted

![Baseline standing admins](screenshots/phase1-standing-global-admins.png)
![Empty CA policy list](screenshots/phase1-no-ca-policies.png)

Captured the Identity Secure Score at this point as the starting metric.

---

## Phase 2: Access control hardening

Built Conditional Access from scratch rather than templates, so every condition and grant was a decision I made.

| Policy | Target | Control |
|---|---|---|
| CA01 | Directory roles (GA, Priv Role Admin, User Admin, Helpdesk, Security Admin) | Require MFA |
| CA02 | All users | Require MFA |
| CA03 | All users, legacy client apps | Block access |
| CA04 | All users outside trusted named location | Block access |
| CA05 | User risk: High | Require password change |
| CA06 | Sign-in risk: Medium and High | Require MFA |

Every policy was staged in report-only mode first, validated against sign-in logs, then enforced. A dedicated break-glass Global Administrator was created and excluded from all policies before anything moved to enforced.

**CA03 was the highest-value single policy.** Legacy protocols (IMAP, POP3, SMTP AUTH, Exchange ActiveSync) authenticate in a way that cannot satisfy an MFA challenge, so leaving them open makes every MFA policy above bypassable.

**Migration note:** the legacy Identity Protection user risk and sign-in risk policy blades are now read-only and retire October 1, 2026. I rebuilt both as Conditional Access policies (CA05, CA06) using the User risk and Sign-in risk conditions, which is where Microsoft has consolidated the functionality.

![CA policy list](screenshots/phase2-ca-policies.png)
![Identity Protection deprecation and CA migration](screenshots/phase2-risk-policy-migration.png)

---

## Phase 3: Privileged Identity Management

The core of the build. Goal was zero standing access: nobody holds a privileged role permanently, they activate it when needed and it expires on its own.

**Right-sizing against the roster.** The IT admin's permanent Global Administrator became an eligible assignment. The helpdesk account lost Global Administrator entirely and received eligible Helpdesk Administrator instead, which is what the job function actually required. Standing active assignments were then removed, since eligible-plus-still-permanent is not an improvement.

**Activation controls configured on Global Administrator:**

- Maximum activation duration reduced from the 8-hour default
- MFA required at activation
- Written justification required
- Approval required, routed to a named approver other than the requestor

**Tested the full loop end to end.** Signed in as the eligible user, requested activation with a written justification, hit the MFA challenge, and landed in a pending state. Approved from a separate session as the designated approver. Confirmed the role went active with an expiry timestamp and a manual deactivate option.

![PIM eligible assignments](screenshots/phase3-eligible-assignments.png)
![Activation request with justification](screenshots/phase3-activation-justification.png)
![Pending approval](screenshots/phase3-pending-approval.png)
![Active role with expiry](screenshots/phase3-active-with-expiry.png)

**What the approval gate buys you:** time-bound activation alone already beats standing access, since a compromised account only holds privilege during a bounded window and every elevation carries an audit trail. Adding approval means a compromised eligible account still cannot elevate without a second person signing off. I configured instant JIT first, then hardened to approval-gated for the most privileged role, which is how I would tier it in production.

---

## Phase 4: Access recertification

Configured a recurring access review against privileged role assignments, launched from PIM rather than the general Identity Governance surface, since privileged role reviews are scoped separately.

- Scope: Global Administrator, all active and eligible assignments
- Reviewer: designated approver, not the role holders themselves
- Recurrence: monthly
- Auto-apply results: enabled, so denials revoke access rather than sitting as advisory findings
- No response behavior: remove access (deny by default)
- Reason required on approval

Self-review was available and rejected. Asking someone to certify their own privilege is the weakest form of attestation, and independent review is the separation of duties the control exists to create.

![Access review configuration](screenshots/phase4-review-config.png)
![Reviewer decisions](screenshots/phase4-reviewer-decisions.png)

This is the closest free analog to a SailPoint certification campaign, and the concepts carry directly: periodic attestation, designated reviewers, automated remediation of denied access.

---

## Phase 5: Identity detections

Exported tenant telemetry to Log Analytics and wrote detections for the abuse patterns the controls above are meant to stop. Diagnostic settings forward AuditLogs, SignInLogs, NonInteractiveUserSignInLogs, RiskyUsers, and UserRiskEvents.

Diagnostic settings are not retroactive, so I generated activity after enabling the export: PIM activations, test sign-ins, and policy changes.

### Detection content

| Detection | Data source | MITRE ATT&CK |
|---|---|---|
| Privileged role activated via PIM | AuditLogs | T1078 Valid Accounts |
| PIM activation outside business hours | AuditLogs | T1078 Valid Accounts |
| Standing privileged role assignment created | AuditLogs | T1098 Account Manipulation |
| Legacy authentication attempt | SigninLogs | T1078 Valid Accounts |
| Risky sign-in that succeeded | SigninLogs | T1078.004 Cloud Accounts |
| MFA fatigue / repeated push denials | SigninLogs | T1621 MFA Request Generation |

**Privileged role activation via PIM**

```kql
AuditLogs
| where OperationName has "Add member to role completed (PIM activation)"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend RoleName = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, RoleName
| sort by TimeGenerated desc
```

**Standing privileged assignment created outside the JIT model**

```kql
AuditLogs
| where OperationName in ("Add member to role", "Add eligible member to role in PIM completed")
| mv-expand TargetResources
| where tostring(TargetResources.displayName) in ("Global Administrator","Privileged Role Administrator","Company Administrator")
| project TimeGenerated, InitiatedBy=tostring(InitiatedBy.user.userPrincipalName), OperationName, Role=tostring(TargetResources.displayName)
```

Global Administrator surfaces as `Company Administrator` in some directory events, so both names are matched to avoid gaps.

**Legacy authentication attempt**

```kql
SigninLogs
| where ClientAppUsed in ("Other clients","IMAP4","POP3","SMTP","Exchange ActiveSync","Authenticated SMTP")
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, ResultType, ResultDescription
| sort by TimeGenerated desc
```

Doubles as validation that CA03 is firing. In a tenant where legacy auth is blocked by policy, attempts against it are usually someone probing for the MFA bypass.

**MFA fatigue**

```kql
SigninLogs
| where ResultType == 500121
| summarize DeniedAttempts = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| where DeniedAttempts >= 5
```

**Risky sign-in that still succeeded**

```kql
SigninLogs
| where RiskLevelDuringSignIn in ("high","medium")
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, RiskLevelDuringSignIn, IPAddress, Location=tostring(LocationDetails.countryOrRegion)
```

![Diagnostic settings export](screenshots/phase5-diagnostic-settings.png)
![PIM activation detection results](screenshots/phase5-pim-detection.png)

The PIM activation I performed in Phase 3 is the event the first query returns. The control and the detection are the same story from two sides.

---

## Results

| Metric | Before | After |
|---|---|---|
| Standing Global Administrators | 3 | 1 (break-glass) |
| Conditional Access policies | 0 | 6 |
| MFA enforcement | None | All users, admins gated separately |
| Legacy auth | Open | Blocked |
| Privileged access model | Permanent | Eligible, MFA and justification, approval gated, auto-expiring |
| Recertification | None | Monthly, auto-remediating |
| Identity Secure Score | See screenshots | See screenshots |

---

## Notes and limitations

Worth stating plainly, since a lab is not production:

- PIM, Identity Protection, and risk-based Conditional Access all require P2 or Entra ID Governance licensing. None of this is reachable on the free tier, and the build ran on a 31-day trial.
- A fresh tenant produces no organic risk signal. Identity Protection detections and the geo-block policy are configured correctly but have little to fire on without simulated sign-ins from other locations.
- Access reviews in a tenant of accounts created days earlier surface nothing genuinely stale. The mechanism is what is being demonstrated, not a finding.
- PIM for Groups requires role-assignable, cloud-only groups, set at group creation time and not changeable afterward.
- Entra ID Governance features for guest users now require a linked Azure subscription with separate billing. This tenant is member-only, so it stays inside the trial.

---

## Repository structure

```
entra-pim-lab/
├── README.md
├── screenshots/
│   ├── phase1-standing-global-admins.png
│   ├── phase1-no-ca-policies.png
│   ├── phase2-ca-policies.png
│   ├── phase2-risk-policy-migration.png
│   ├── phase3-eligible-assignments.png
│   ├── phase3-activation-justification.png
│   ├── phase3-pending-approval.png
│   ├── phase3-active-with-expiry.png
│   ├── phase4-review-config.png
│   ├── phase4-reviewer-decisions.png
│   ├── phase5-diagnostic-settings.png
│   └── phase5-pim-detection.png
├── detections/
│   ├── pim-activation.kql
│   ├── pim-activation-offhours.kql
│   ├── standing-privileged-assignment.kql
│   ├── legacy-auth-attempt.kql
│   ├── risky-signin-success.kql
│   └── mfa-fatigue.kql
└── docs/
    ├── conditional-access-policies.md
    ├── pim-role-settings.md
    └── access-review-config.md
```

---

## What this covers

Conditional Access policy design and staged rollout, break-glass account practice, just-in-time privileged access with approval workflows, access certification with automated remediation, identity threat detection in KQL, and MITRE ATT&CK mapping of identity techniques.
