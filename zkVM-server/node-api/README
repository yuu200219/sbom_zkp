# Getting started with zkVM-server Node API
## Install the same Node.js version
If you haven't downloaded the `nvm`, you can check https://github.com/nvm-sh/nvm?tab=readme-ov-file#installing-and-updating for reference.
- If you haven't download the corresponding Node.js version
    ```bash
    nvm install
    ```
- If you already downloaded the corresponding Node.js version
    ```bash
    nvm use
    ```
## Initialize the project
```bash
npm init -y
npm install express axios ethers dotenv
npm install --save-dev typescript @types/node @types/express ts-node
npm install --save-dev tsx
npm install kubo-rpc-client
npx tsc --init
```
## Modify `package.json`
```JSON
{
  "name": "api",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "test:prove": "tsx scripts/client-test.ts",
    "build": "tsc"
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "description": "",
  "dependencies": {
    "axios": "^1.13.2",
    "dotenv": "^17.2.3",
    "ethers": "^6.16.0",
    "express": "^5.2.1",
    "kubo-rpc-client": "^6.0.2"
  },
  "devDependencies": {
    "@types/express": "^5.0.6",
    "@types/node": "^25.0.9",
    "ts-node": "^10.9.2",
    "tsx": "^4.21.0",
    "typescript": "^5.9.3"
  },
  "type": "module"
}
```
## run code
- Formally, we will run the `node-api` with `docker-compose.yml` from parent directory.
- For develope stage
    ```bash
    npm run dev
    ```
- For build stage
    ```bash
    npm run build
    ```
- To run the client test script
    ```bash
    npm run test:prove
    ```
