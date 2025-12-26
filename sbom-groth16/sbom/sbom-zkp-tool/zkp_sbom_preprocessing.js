const fs = require('fs');
const { buildPoseidon } = require('circomlibjs');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

// 設定 CLI 參數解析
const argv = yargs(hideBin(process.argv))
    .option('input', {
        alias: 'i',
        description: 'Input SBOM JSON path',
        type: 'string',
        demandOption: true
    })
    .option('output', {
        alias: 'o',
        description: 'Output SBOM JSON path',
        type: 'string',
        demandOption: true
    })
    .help()
    .alias('help', 'h')
    .argv;

async function main() {
    // 1. 初始化 Poseidon (它是非同步的)
    const poseidon = await buildPoseidon();
    const F = poseidon.F; // Field arithmetic interface

    // 讀取 SBOM
    const rawData = fs.readFileSync(argv.input);
    const sbom = JSON.parse(rawData);

    console.log(`[-] Processing SBOM: ${argv.input}`);
    let count = 0;

    // 遍歷所有 components
    if (sbom.components) {
        for (const component of sbom.components) {
            
            // --- 關鍵邏輯：尋找 SHA-256 Hash ---
            // 為了確保真實性，我們拿官方工具 (Syft) 算好的 SHA-256 來當作 Poseidon 的輸入
            // 這比自己重新組字串 (String) 更安全，因為 ZK 電路很難處理不定長度字串
            
            let sha256Content = null;
            if (component.hashes) {
                if (!(component.type === 'library')) {
                    console.warn(`[!] Component ${component.name} is not a library, skipping.`);
                    continue;
                }
                else {
                    const hashObj = component.hashes.find(h => h.alg === 'SHA-256');
                    if (hashObj) {
                        sha256Content = hashObj.content;
                    }
                }
                
            }

            if (sha256Content) {
                // --- ZK Transform Logic ---
                // SHA-256 (Hex string) -> 2 chunks of BigInt -> Poseidon Hash
                
                // 1. 切割 Hex String (前128位, 後128位)
                // sha256 是 64 個 hex 字元 (每字元 4 bits = 256 bits)
                // 我們切成 32 chars + 32 chars
                const part1Hex = sha256Content.substring(0, 32);
                const part2Hex = sha256Content.substring(32, 64);

                // 2. 轉成 BigInt
                const input1 = BigInt('0x' + part1Hex);
                const input2 = BigInt('0x' + part2Hex);

                // 3. 計算 Poseidon([in1, in2])
                const poseidonResult = poseidon([input1, input2]);

                // 4. 將結果轉回 String (十進位字串，方便儲存)
                const poseidonStr = F.toString(poseidonResult);

                // --- 注入 Properties ---
                if (!component.properties) {
                    component.properties = [];
                }

                // 加入 Poseidon Hash
                component.properties.push({
                    "name": "research:zkp:hash:poseidon",
                    "value": poseidonStr
                });

                // (Optional) 加入切割後的輸入值，方便電路作為 Private Witness 輸入
                component.properties.push({
                    "name": "research:zkp:witness:part1",
                    "value": input1.toString()
                });
                component.properties.push({
                    "name": "research:zkp:witness:part2",
                    "value": input2.toString()
                });

                count++;
            } else {
                console.warn(`[!] Component ${component.name} has no SHA-256 hash, skipping Poseidon calculation.`);
            }
        }
    }

    // 寫入檔案
    fs.writeFileSync(argv.output, JSON.stringify(sbom, null, 2));
    console.log(`[+] Success! Processed ${count} components.`);
    console.log(`[+] Output saved to: ${argv.output}`);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});