# PoC: Bull SDK `attest()` — smuggled approve + createAgreement actions (B-08)

The Bull SDK states: "the API server is not trusted with your wallet.
Every transaction it returns is checked before it is sent."

`attest()` breaks that promise. It fetches the agreement's conditions and
actions from the API (`GET /api/v1/agreements/{id}`) and filters them only
by `from == me` and `name != "object"` — and the server controls the
`name`. Each surviving action goes straight to `#send()` with the default
`maxWei = 0` and no `spenderOnly`. `#guard` permits an
`approve(token → Agreement, < 2**200)` and any value-0 call to the
Agreement contract, and it never inspects calldata sent to a Bull contract.

A compromised/malicious API server appends two extra actions — both named
`"attest"` — to a legit confirmation:

1. `approve(USDC → Agreement, 5,000)` — passes `#guard`.
2. `createAgreement(payee = attacker, amount = 5,000, condition
   attest-by-attacker)` — passes `#guard`.

The victim called `bull.attest("1")` intending a ZERO-VALUE confirmation
that delivery happened on their existing agreement. Instead the SDK sent
all three actions with NO error and NO warning, and locked 5,000 tokens
into an attacker-controlled agreement. The attacker attests and releases
them to themselves. The same smuggle works through `vote()` / `object()`,
which share the `attest()` code path (same finding, not filed separately).

Why this is NOT a duplicate of B-03 (`fund()`), B-04 (`agree()`) or B-07
(`deal()`): different function (`attest()`), different victim flow
(confirming delivery on an EXISTING agreement — an action the user believes
moves no funds at all), and a different mechanism (action smuggling through
the name filter). Fixing `agree()` / `deal()` does not touch `attest()`.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start a FRESH Anvil (Foundry) on port 8547 — restart between runs.
#    The mock Agreement is etched at the production address; re-running on
#    a used chain collides with the previous run's stored agreement
#    (stale released flag + conditions array).
anvil --port 8547 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockAgreement` (etched at the production Agreement address so
   the real SDK's guard accepts it) + `MockERC20`, mints 10,000 tokens to
   the victim; victim creates legit agreement 1 directly (pay 500 to a
   contractor, attest by the victim).
2. Victim calls `bull.attest("1")` via the **real** SDK (`bull-sdk.mjs`,
   verbatim copy of https://www.bull.family/sdk/bull.mjs). The mock API
   returns the legit attest action PLUS 2 smuggled actions; the SDK sends
   all 3 with NO ERROR, NO WARNING.
3. Attacker attests (id 2, index 0) then releases id 2.

## Result (verified run, 16 Nov 2026)

```
SDK attest() returned 3 tx hashes — NO ERROR, NO WARNING
smuggled agreement 2: payee == attacker: true, amount 5000
victim token balance before attest(): 9500 (10,000 - 500 legit lock)
victim token balance after attest(): 4500
attacker token balance: 5000
contractor token balance: 0
EXPLOITED
```

## Files

- `run-poc.mjs` — the PoC driver (real SDK + mock Agreement on Anvil)
- `mock-api.mjs` — mock Bull API (legit action + 2 smuggled actions)
- `bull-sdk.mjs` — verbatim copy of https://www.bull.family/sdk/bull.mjs
- `chain/src/MockAgreement.sol` — mock Agreement (documented semantics)
- `chain/src/Mocks.sol` — MockERC20
- `poc-result.json` — machine-readable result of the last run

## Honest scope note

The real BullAgreement source is NOT verified anywhere (Sourcify and
Blockscout return no match), so this PoC uses a mock implementing the
DOCUMENTED Agreement semantics from https://www.bull.family/llms.txt. The
claim proven here is the SDK's missing verification — demonstrated with the
real SDK sending the server's smuggled actions — not the mock's internals.

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (repo) **only together with the
report submission**, after the user approves the draft — never before
(public disclosure only after the report is sent).
