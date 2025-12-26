const fs = require('fs');
const { buildPoseidon } = require('circomlibjs');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const argv = yargs(hideBin(process.argv))
    .option('input', { alias: 'i', type: 'string', demandOption: true, description: 'Processed SBOM (with Poseidon hashes)' })
    .option('output', { alias: 'o', type: 'string', demandOption: true, description: 'File to save Root and Merkle Paths' })
    .option('dot', { alias: 'd', type: 'string', description: '(Optional) Output path for DOT visualization file' })
    .argv;

// 輔助函式：截斷 Hash 以方便顯示
function shortHash(bigIntStr) {
    const s = bigIntStr.toString();
    if (s.length <= 10) return s;
    return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // 1. 讀取 SBOM
    const sbom = JSON.parse(fs.readFileSync(argv.input));

    // 2. 提取 Leaves (同時記錄對應的組件資訊)
    let leaves = [];
    let leafInfo = []; // 新增：用來正確對應 Component 資訊

    for (const comp of sbom.components) {
        // --- FIX 1: 檢查 properties 是否存在 ---
        if (comp.properties) {
            const pProp = comp.properties.find(p => p.name === 'research:zkp:hash:poseidon');
            if (pProp) {
                leaves.push(BigInt(pProp.value));
                // --- FIX 2: 同步記錄組件資訊，避免索引錯亂 ---
                leafInfo.push({
                    name: comp.name,
                    version: comp.version
                });
            }
        }
    }

    let realLeafCount = leaves.length;

    if (leaves.length === 0) {
        console.error("No Poseidon hashes found in SBOM. Did you run zkp_preprocessor.js?");
        return;
    }

    console.log(`[-] Building Merkle Tree from ${realLeafCount} real leaves...`);

    // 3. 補齊至 2 的冪次方
    let nextPowerOf2 = 1;
    while (nextPowerOf2 < leaves.length) {
        nextPowerOf2 *= 2;
    }
    
    // Padding
    while (leaves.length < nextPowerOf2) {
        leaves.push(BigInt(0));
    }

    // --- DOT 生成準備 ---
    let dotOutput = 'digraph MerkleTree {\n';
    dotOutput += '    node [fontname="Arial"];\n';
    dotOutput += '    rankdir=BT; // Bottom-Up 方向\n';

    // 定義葉子節點樣式
    for (let i = 0; i < leaves.length; i++) {
        const nodeId = `L0_${i}`;
        const hashLabel = shortHash(leaves[i]);
        
        if (i < realLeafCount) {
            // 真實節點顯示組件名稱 (從 leafInfo 拿，而不是 sbom.components)
            const compName = leafInfo[i].name; 
            dotOutput += `    "${nodeId}" [label="${compName}\\n${hashLabel}", shape=box, style=filled, fillcolor="#e6f3ff", color="#0066cc"];\n`;
        } else {
            dotOutput += `    "${nodeId}" [label="Padding\\n0", shape=box, style="dashed,filled", fillcolor="#f0f0f0", fontcolor="#999999"];\n`;
        }
    }

    // 4. 建樹
    const layers = [leaves];
    let currentLayer = leaves;
    let layerIndex = 0;

    while (currentLayer.length > 1) {
        const nextLayer = [];
        const nextLayerIndex = layerIndex + 1;

        for (let i = 0; i < currentLayer.length; i += 2) {
            const left = currentLayer[i];
            const right = currentLayer[i + 1];
            
            const hash = poseidon([left, right]);
            const hashBigInt = F.toObject(hash);
            nextLayer.push(hashBigInt);

            // DOT 內部節點
            const parentId = `L${nextLayerIndex}_${i/2}`;
            const leftId = `L${layerIndex}_${i}`;
            const rightId = `L${layerIndex}_${i+1}`;
            const label = shortHash(hashBigInt);

            dotOutput += `    "${parentId}" [label="${label}", shape=ellipse];\n`;
            dotOutput += `    "${leftId}" -> "${parentId}";\n`;
            dotOutput += `    "${rightId}" -> "${parentId}";\n`;
        }
        layers.push(nextLayer);
        currentLayer = nextLayer;
        layerIndex++;
    }

    const root = currentLayer[0];
    const rootStr = root.toString();

    // DOT Root 樣式
    const rootId = `L${layerIndex}_0`;
    dotOutput += `    "${rootId}" [label="ROOT\\n${shortHash(root)}", shape=diamond, style=filled, fillcolor="#fff3e6", color="#ff9900", penwidth=2];\n`;
    dotOutput += '}\n';

    console.log(`[+] Merkle Root: ${rootStr}`);

    // 5. 生成 Path 並儲存 JSON
    const outputData = {
        merkleRoot: rootStr,
        components: []
    };

    // --- FIX 3: 使用正確的迴圈範圍與資料源 ---
    // 只遍歷真實的 leaves (realLeafCount)
    for (let i = 0; i < realLeafCount; i++) {
         const pathElements = [];
         const pathIndices = [];
         
         let currentIndex = i;
         for (let L = 0; L < layers.length - 1; L++) {
             const isRightNode = currentIndex % 2 === 1;
             const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
             
             const sibling = layers[L][siblingIndex];
             pathElements.push(sibling.toString());
             pathIndices.push(isRightNode ? 1 : 0);
             
             currentIndex = Math.floor(currentIndex / 2);
         }

         outputData.components.push({
             name: leafInfo[i].name,       // 從 leafInfo 拿資料
             version: leafInfo[i].version, // 從 leafInfo 拿資料
             merklePath: {
                 pathElements: pathElements,
                 pathIndices: pathIndices
             }
         });
    }

    fs.writeFileSync(argv.output, JSON.stringify(outputData, null, 2));
    console.log(`[+] Tree data saved to ${argv.output}`);

    if (argv.dot) {
        fs.writeFileSync(argv.dot, dotOutput);
        console.log(`[+] DOT visualization saved to ${argv.dot}`);
    }
}

main().catch(console.error);