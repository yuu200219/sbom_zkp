import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      evmVersion: "paris",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    qbft: {
      url: "http://127.0.0.1:8545",
      chainId: 1337,
      accounts: [
        "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63",
        "c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3",
        "ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f",
      ],
    },
  },
};

export default config;
