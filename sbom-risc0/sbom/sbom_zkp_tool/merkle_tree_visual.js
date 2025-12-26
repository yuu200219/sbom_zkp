const fs = require('fs');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const crypto = require('crypto');

function sha256(left, right) {
    if (!left || !right) {
        throw new Error(`Hash error: Received undefined. Left: ${left}, Right: ${right}`);
    }
    // 確保輸入是字串，且移除 0x 前綴
    const l = left.toString().replace('0x', '');
    const r = right.toString().replace('0x', '');
    // 將輸入轉為 Buffer
    const buffer = Buffer.concat([
        Buffer.from(l, 'hex'),
        Buffer.from(r, 'hex')
    ]);
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

function shortName(s, max=40) {
  if (!s) return "";
  // 若是路徑，取最後兩層
  const parts = s.split(/[\\/]/).filter(Boolean);
  const tail = parts.slice(-2).join("/");
  if (tail.length <= max) return tail;
  return tail.slice(0, 20) + "..." + tail.slice(-15);
}

const argv = yargs(hideBin(process.argv))
    .option('input', { alias: 'i', type: 'string', demandOption: true, description: 'Processed SBOM' })
    .option('output', { alias: 'o', type: 'string', demandOption: true, description: 'File to save Root and Merkle Paths' })
    .option('dot', { alias: 'd', type: 'string', description: '(Optional) Output path for DOT visualization file' })
    .argv;

const DROP_NAMES = new Set(["pip", "setuptools", "wheel"]);     // 你想排除的套件
const DROP_TYPES = new Set(["file"]);                           // 如果 syft 產生 file component 可直接剃掉
const DROP_PURL_PREFIXES = ["file:", "exe:", "generic:"];       // 保險：排除非套件類 purl

// 輔助函式：截斷 Hash 以方便顯示
function shortHash(bigIntStr) {
    const s = bigIntStr.toString();
    if (s.length <= 10) return s;
    return `${s.slice(0, 6)}...${s.slice(-4)}`;
}

async function main() {

    // 1. 讀取 SBOM
    const sbom = JSON.parse(fs.readFileSync(argv.input));

    // 2. 提取 Leaves (同時記錄對應的組件資訊)
    let leaves = [];
    let leafInfo = []; // 新增：用來正確對應 Component 資訊

    for (const comp of sbom.components) {
        const name = (comp?.name || "").toLowerCase();
        const type = (comp?.type || "").toLowerCase();
        const purl = (comp?.purl || "").toLowerCase();

        // FILTER START
        if (!name) continue;                     // 沒名字通常不是套件（或是垃圾節點）
        if (DROP_NAMES.has(name)) continue;      // 排除 pip / setuptools / wheel
        if (type && DROP_TYPES.has(type)) continue;

        // 只保留 Python 套件層（你如果確定只做 Python，這個很有效）
        // CycloneDX 的 purl 可能長這樣: pkg:pypi/flask@2.0.1
        // if (purl && !purl.startsWith("pkg:pypi/")) continue;
        // 保險：排除 file/exe 類
        if (DROP_PURL_PREFIXES.some(pre => purl.startsWith(pre))) continue;
        // FILTER END
        
        //  必須要有 SHA-256 雜湊值
        if (comp.hashes) {
            const pProp = comp.hashes.find(p => p.alg === 'SHA-256');
            if (pProp && pProp.content) {
                // 確保只存入「字串」，並去除 0x
                const cleanHash = pProp.content.toString().replace('0x', '').trim();
                leaves.push(cleanHash);
                leafInfo.push({
                    name: comp.name,
                    version: comp.version
                });
            }
        }
    }

    const realLeafCount = leaves.length;
    if (realLeafCount === 0) {
        console.error("No hashes found!");
        return;
    }
    

    console.log(`[-] Building Merkle Tree from ${realLeafCount} real leaves...`);

    // 3. 補齊至 2 的冪次方
    let nextPowerOf2 = 1;
    while (nextPowerOf2 < realLeafCount) {
        nextPowerOf2 *= 2;
    }
    
    // Padding
    const PADDING_VALUE = '0'.repeat(64); // 32 bytes of zeros
    console.log(`[-] Real leaves: ${realLeafCount}, Padding to: ${nextPowerOf2}`);

    while (leaves.length < nextPowerOf2) {
        leaves.push(PADDING_VALUE);
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
            // const compName = leafInfo[i].name; 
            const name = shortName(leafInfo[i].name);
            const ver = leafInfo[i].version;
            const title = ver ? `${name}@${ver}` : name;
            dotOutput += `    "${nodeId}" [label="${title}\\n${hashLabel}", shape=box, style=filled, fillcolor="#e6f3ff", color="#0066cc"];\n`;
        } else {
            dotOutput += `    "${nodeId}" [label="Padding\\n0", shape=box, style="dashed,filled", fillcolor="#f0f0f0", fontcolor="#999999"];\n`;
            // dotOutput += `    "${nodeId}" [label="", style=invis, width=0, height=0];\n`;
        }
    }

    // 4. 建樹
    const layers = [leaves];
    let currentLayer = leaves;
    let layerIndex = 0;

    while (currentLayer.length > 1) {
        const nextLayer = [];
        console.log(`[-] Processing Layer ${layerIndex}, count: ${currentLayer.length}`);

        for (let i = 0; i < currentLayer.length; i += 2) {
            const left = currentLayer[i];
            const right = currentLayer[i + 1];

            // 如果這裡噴 undefined，代表 Padding 沒補齊
            if (left === undefined || right === undefined) {
                throw new Error(`Layer ${layerIndex} index ${i} is missing children! Left: ${left}, Right: ${right}`);
            }

            // 確保傳入的是單一字串而非陣列
            if (Array.isArray(left)) throw new Error(`Data error: Left is an array at index ${i}`);

            const hashHex = sha256(left, right);
            nextLayer.push(hashHex);

            // DOT 邏輯...
            const parentIndex = i / 2;
            const parentId = `L${layerIndex + 1}_${parentIndex}`;
            const leftId = `L${layerIndex}_${i}`;
            const rightId = `L${layerIndex}_${i + 1}`;

            // parent node（中間層）
            dotOutput += `    "${parentId}" [label="${shortHash(hashHex)}", shape=box, style="filled", fillcolor="#ffffff", color="#666666"];\n`;

            // edges：child -> parent
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
             hash: leaves[i].toString().replace('0x', ''),
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