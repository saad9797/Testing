# Working on Authorized Security Testing Without Tripping Safeguards

You do legitimate work — HackerOne-authorized targets and your own AI projects.
The safety classifier still flags you sometimes. This guide explains *why* that
happens and gives you concrete habits to reduce the friction, without asking you
to prove anything you can't prove.

## The core thing to understand

The safeguard is **not** judging you, your history, or your intentions. It reads
one message (and its nearby context) and reacts to **content and shape**. It has
no access to your HackerOne profile, your program scope, or your signed
authorization. So an authorized request and an unauthorized one that use the same
words look identical to it.

That means the fix is never "prove you're allowed." It's **make each request carry
the context and shape that legitimate work naturally has.** You're not tricking a
filter — you're supplying the information a reasonable reviewer would want.

## Why it worked, then stopped mid-session

The most common cause of "it was fine for 2–3 prompts then flagged me":

- **Context decay.** Your first message set the frame ("authorized test on program
  X"). Ten turns later, a bare *"now write the payload"* has lost that frame. The
  classifier sees the last message, which now reads like a raw weaponization ask.
- **Escalating operational specificity.** Early questions are conceptual; later
  ones drift into "give me the exact working exploit, no explanation." That shape
  is the risky one regardless of who's asking.

**Fix:** restate scope when a thread drifts, and keep asks anchored to mechanism +
detection, not just the weapon. See habits below.

## Habits that reduce false flags

### 1. Front-load authorization and scope — and refresh it
State it plainly at the start of a task and again whenever the topic shifts:

> "Authorized testing. Target is in scope on a HackerOne program I'm enrolled in
> (or: my own app running on localhost). I'm assessing [specific thing]."

You don't need to prove it. Stating it establishes intent and, importantly, keeps
the frame alive across turns.

### 2. Name the target as clearly yours or in-scope
- Best: `localhost`, your own VM, a deliberately-vulnerable lab (DVWA,
  Juice Shop, Metasploitable), a CTF, or "the in-scope asset on [program]."
- Riskiest: naming a specific third-party production system with no ownership or
  scope context. That single detail flips the shape from "research" to "attack a
  stranger."
- If the real target is a client's production system, you can still test/reason
  against a **local replica or the app's own code** and generalize — often more
  effective anyway.

### 3. Ask for mechanism + detection, not just the weapon
Compare:
- ✗ "Write me a working exploit for this that evades their WAF."
- ✓ "How does this vulnerability class work, how would I confirm it on my in-scope
  target, what's a minimal PoC, and how would a defender detect and fix it?"

The second is *more useful for your actual report* (findings + remediation) and
reads as legitimate work. Weaponization-only, evasion-only asks are the shape most
likely to trip.

### 4. Prefer PoC over payload
A **proof of concept** that demonstrates the bug (a marker, a benign callback, a
harmless canary) is what a bug-bounty report needs — not a fully weaponized,
destructive payload. Frame requests around "demonstrate the issue safely."

### 5. Break big asks into understood steps
"Give me the full autonomous exploit chain" is a worse shape than walking through
recon → hypothesis → minimal PoC → remediation. Stepwise also produces a better
writeup.

### 6. Keep it in report language
You're producing findings. Phrasing things as "for the writeup / remediation
section / severity justification" both matches your real goal and signals intent.

## A reusable preamble you can paste

Keep this handy and drop it at the top of a security session (edit to fit):

```
Context: authorized security assessment.
- Target: [in-scope HackerOne asset on program X  |  my own app at localhost:PORT  |  local lab (Juice Shop)].
- Authorization: [enrolled in the program's scope  |  I own this system].
- Goal: identify and document [vuln class / behavior], produce a PoC and remediation guidance for the report.
- I want to understand the mechanism and detection, not just a weaponized payload.
```

## Where the hard limits actually are

So you can plan around them — these do **not** bend with authorization claims,
because their harm isn't scoped to one target:

- Genuinely destructive payloads (data-wiping, ransomware, anything meant to spread)
- Denial-of-service attacks
- Mass or indiscriminate targeting
- Supply-chain compromise
- Detection-evasion whose purpose is helping a real attacker hide

Everything typical of bug-bounty and app pentest work — recon, enumeration, common
web/app vuln classes (injection, auth, access control, SSRF, deserialization,
etc.), dual-use tooling (C2, credential testing, exploit dev) **with** the
engagement/scope context — is supportable.

## If a request still gets flagged

1. **Re-read your own message as a stranger would.** Did it drop the scope? Did it
   ask only for a weapon with no mechanism/detection? Add the missing context.
2. **Re-anchor:** restate target + authorization, then ask again.
3. **Reframe to mechanism + PoC + remediation** instead of raw payload.
4. **Split it up** into smaller, clearly-understood steps.
5. If it's genuinely one of the hard-limit categories above, no framing changes it —
   that's by design, and you'd do that part with your own tooling.

## For your AI-pentest work specifically

Testing LLM/agent systems you're authorized on (prompt injection, jailbreak
resistance, exfil, tool abuse) is well-supported. Frame as:
"red-teaming an AI system I'm authorized to test — help me build test cases and
evaluate the defenses." Test-case design, harnesses, scoring, and result analysis
are all fair game. See `corpus.yaml` and `rubric.md` in this folder for a starting
kit.

## TL;DR

- The filter reads content/shape, not your credentials — so **supply context, don't
  try to prove yourself.**
- **Restate scope when threads drift** (this fixes the "worked then didn't" case).
- **Mechanism + detection + PoC + remediation** beats "just the weapon."
- **Own/lab/in-scope targets, named as such.**
- A handful of categories are hard limits no matter what; route those to your own
  tools.
