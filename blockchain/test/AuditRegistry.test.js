const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AuditRegistry", function () {
  let registry;
  let owner;

  beforeEach(async function () {
    [owner] = await ethers.getSigners();
    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    registry = await AuditRegistry.deploy();
    await registry.waitForDeployment();
  });

  it("registers an assessment and emits an event", async function () {
    const assessmentId = "test-assessment-1";
    const reportHash = "a".repeat(64);

    await expect(registry.registerAssessment(assessmentId, reportHash))
      .to.emit(registry, "AssessmentRegistered")
      .withArgs(assessmentId, reportHash, anyUint(), owner.address);
  });

  it("retrieves a registered assessment", async function () {
    const assessmentId = "test-assessment-2";
    const reportHash = "b".repeat(64);

    await registry.registerAssessment(assessmentId, reportHash);
    const [storedHash, timestamp, registeredBy] = await registry.getAssessment(assessmentId);

    expect(storedHash).to.equal(reportHash);
    expect(registeredBy).to.equal(owner.address);
    expect(timestamp).to.be.greaterThan(0);
  });

  it("verifies a matching hash as true", async function () {
    const assessmentId = "test-assessment-3";
    const reportHash = "c".repeat(64);

    await registry.registerAssessment(assessmentId, reportHash);
    const matches = await registry.verifyHash(assessmentId, reportHash);
    expect(matches).to.equal(true);
  });

  it("verifies a tampered hash as false", async function () {
    const assessmentId = "test-assessment-4";
    const reportHash = "d".repeat(64);
    const tamperedHash = "e".repeat(64);

    await registry.registerAssessment(assessmentId, reportHash);
    const matches = await registry.verifyHash(assessmentId, tamperedHash);
    expect(matches).to.equal(false);
  });

  it("reverts when registering the same assessment ID twice", async function () {
    const assessmentId = "test-assessment-5";
    await registry.registerAssessment(assessmentId, "f".repeat(64));

    await expect(
      registry.registerAssessment(assessmentId, "g".repeat(64))
    ).to.be.revertedWith("assessment already registered");
  });
});

// Helper to match any uint256 in event args (hardhat-chai-matchers doesn't
// export this directly in all versions, so provide a tiny local shim).
function anyUint() {
  return {
    asymmetricMatch: (value) => {
      try {
        BigInt(value);
        return true;
      } catch {
        return false;
      }
    },
    toString: () => "<any uint>",
  };
}
