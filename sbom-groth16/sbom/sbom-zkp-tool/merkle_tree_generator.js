const fs = require('fs');
const { buildPoseidon } = require('circomlibjs');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const argv = yargs(hideBin(process.argv))
    .option('input', { alias: 'i', type: 'string', demandOption: true, description: 'Processed SBOM (with Poseidon hashes)' })
    .option('output', { alias: 'o', type: 'string', demandOption: true, description: 'File to save Root and Merkle Paths' })
    .argv;

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // 1. 讀取已經注入 Poseidon Hash 的 SBOM
    const sbom = JSON.parse(fs.readFileSync(argv.input));

    // 2. 提取所有的 Leaves (Poseidon Hashes)
    let leaves = [];
    for (const comp of sbom.components) {
        const pProp = comp.properties.find(p => p.name === 'research:zkp:hash:poseidon');
        if (pProp) {
            leaves.push(BigInt(pProp.value));
        }
    }

    if (leaves.length === 0) {
        console.error("No Poseidon hashes found in SBOM. Did you run zkp_preprocessor.js?");
        return;
    }

    console.log(`[-] Building Merkle Tree from ${leaves.length} leaves...`);

    // 3. 補齊樹葉數量至 2 的冪次方 (Pad to power of 2)
    // Merkle Tree 通常需要平衡，不足的補 0
    let nextPowerOf2 = 1;
    while (nextPowerOf2 < leaves.length) {
        nextPowerOf2 *= 2;
    }
    
    // 填充 0 (Zero Node)
    while (leaves.length < nextPowerOf2) {
        leaves.push(BigInt(0));
    }

    // 4. 建樹 (簡單的遞迴或迴圈層層 Hash)
    const layers = [leaves]; // 第 0 層是葉子
    
    let currentLayer = leaves;
    while (currentLayer.length > 1) {
        const nextLayer = [];
        for (let i = 0; i < currentLayer.length; i += 2) {
            const left = currentLayer[i];
            const right = currentLayer[i + 1];
            
            // 重要：樹的節點 Hash 也必須用 Poseidon
            const hash = poseidon([left, right]);
            nextLayer.push(F.toObject(hash)); // 轉成 BigInt 儲存
        }
        layers.push(nextLayer);
        currentLayer = nextLayer;
    }

    const root = currentLayer[0]; // 頂層唯一的元素就是 Root
    const rootStr = root.toString();

    console.log(`[+] Merkle Root: ${rootStr}`);

    // 5. (選擇性) 為每個組件生成 Merkle Path 並存回 JSON
    // 為了 ZKP Private Input，您需要知道每個組件的路徑
    const outputData = {
        merkleRoot: rootStr,
        components: []
    };

    // 簡單的 Path 生成邏輯
    for (let i = 0; i < leaves.length; i++) {
        // 只處理原本存在的 components (忽略 padding 的)
        if (i < sbom.components.length && sbom.components[i].properties) {
             const pathElements = [];
             const pathIndices = [];
             
             let currentIndex = i;
             // 遍歷每一層 (排除 Root 層)
             for (let L = 0; L < layers.length - 1; L++) {
                 const isRightNode = currentIndex % 2 === 1;
                 const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
                 
                 const sibling = layers[L][siblingIndex];
                 pathElements.push(sibling.toString());
                 pathIndices.push(isRightNode ? 1 : 0);
                 
                 currentIndex = Math.floor(currentIndex / 2);
             }

             outputData.components.push({
                 name: sbom.components[i].name,
                 version: sbom.components[i].version,
                 merklePath: {
                     pathElements: pathElements,
                     pathIndices: pathIndices
                 }
             });
        }
    }

    fs.writeFileSync(argv.output, JSON.stringify(outputData, null, 2));
    console.log(`[+] Tree data saved to ${argv.output}`);
}

main().catch(console.error);