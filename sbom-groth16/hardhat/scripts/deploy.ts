import hre from "hardhat";

async function main() {
  console.log("🚀 開始部署 Counter 合約 (ethers + Hardhat v2)...");

  const Counter = await hre.ethers.getContractFactory("Counter");
  const counter = await Counter.deploy(); // 如果 constructor 有參數，就填在這裡
  
  console.log("正在等待部署完成...");
  await counter.waitForDeployment();

  const address = await counter.getAddress();
  console.log(`✅ Counter 已成功部署到: ${address}`);

  console.log("正在呼叫 incBy(5)...");
  const tx = await counter.incBy(5);
  await tx.wait();

  console.log("✅ incBy(5) 執行成功！");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
