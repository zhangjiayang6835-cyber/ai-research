const { ethers } = require("hardhat");

async function main() {
  const FixedToken = await ethers.getContractFactory("FixedToken");
  const token = await FixedToken.deploy();
  await token.deployed();

  console.log("Token deployed to:", token.address);

  // Example safe transfer (no overflow possible)
  const [owner, addr1] = await ethers.getSigners();
  const tx = await token.transfer(addr1.address, 100);
  await tx.wait();
  console.log("Transfer succeeded without overflow.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
