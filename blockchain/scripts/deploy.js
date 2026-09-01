const hre = require("hardhat");

async function main() {
  const AuditRegistry = await hre.ethers.getContractFactory("AuditRegistry");
  const registry = await AuditRegistry.deploy();
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  console.log("\nAuditRegistry deployed to:", address);
  console.log("\n>>> Copy this address into backend/.env as CONTRACT_ADDRESS <<<\n");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
