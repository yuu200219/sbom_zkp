const fs = require('fs');
const readline = require('readline');
const { buildPoseidon } = require('circomlibjs');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const argv = yargs(hideBin(process.argv))
    .option('input', { alias: 'i', type: 'string', demandOption: true, description: 'Input SBOM JSON path' })
    .option('output', { alias: 'o', type: 'string', demandOption: true, description: 'Output SBOM JSON path' })
    .option('requirements', { alias: 'r', type: 'string', description: 'Path to requirements.txt for hash enrichment' })
    .help()
    .argv;

// 解析 requirements.txt 的輔助函式
async function parseRequirements(filePath) {
    const fileStream = fs.createReadStream(filePath);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    const hashMap = {}; // Key: package name (lowercase), Value: sha256 hex
    let currentPackage = null;

    for await (const line of rl) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        // 匹配套件名稱 (例如: flask==2.0.1)
        // 簡單的正則，抓取 == 前面的名字
        const pkgMatch = trimmed.match(/^([a-zA-Z0-9_\-]+)==/);
        if (pkgMatch) {
            currentPackage = pkgMatch[1].toLowerCase();
        }

        // 匹配 Hash (例如: --hash=sha256:...)
        const hashMatch = trimmed.match(/--hash=sha256:([a-f0-9]{64})/);
        if (hashMatch && currentPackage) {
            // 我們只抓第一個找到的 hash (通常 requirements 會有多個 hash 針對不同平台，這裡假設取第一個作為驗證目標)
            if (!hashMap[currentPackage]) {
                hashMap[currentPackage] = hashMatch[1];
            }
        }
    }
    return hashMap;
}

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // 1. 準備 Hash Map (如果提供了 requirements.txt)
    let externalHashes = {};
    if (argv.requirements) {
        console.log(`[-] Parsing requirements file: ${argv.requirements}`);
        externalHashes = await parseRequirements(argv.requirements);
        console.log(`    Found hashes for ${Object.keys(externalHashes).length} packages.`);
    }

    // 2. 讀取 SBOM
    const rawData = fs.readFileSync(argv.input);
    const sbom = JSON.parse(rawData);

    console.log(`[-] Processing SBOM: ${argv.input}`);
    let count = 0;

    if (sbom.components) {
        for (const component of sbom.components) {
            // 只處理 Library
            if (component.type !== 'library') continue;

            // --- 策略：取得 SHA-256 ---
            let sha256Content = null;

            // A. 優先嘗試從 SBOM 本身讀取 (如果 Syft 未來修復了)
            if (component.hashes) {
                const hashObj = component.hashes.find(h => h.alg === 'SHA-256');
                if (hashObj) sha256Content = hashObj.content;
            }

            // B. 如果 SBOM 裡沒有，從 requirements.txt 的解析結果找
            if (!sha256Content && externalHashes[component.name.toLowerCase()]) {
                sha256Content = externalHashes[component.name.toLowerCase()];
                // 順便補回 hashes 欄位到 JSON 中，讓輸出檔案更完整
                if (!component.hashes) component.hashes = [];
                component.hashes.push({ "alg": "SHA-256", "content": sha256Content });
                // console.log(`    [+] Enriched hash for ${component.name}`);
            }

            if (sha256Content) {
                try {
                    // --- ZKP Poseidon 計算 (跟之前一樣) ---
                    if (sha256Content.length !== 64) throw new Error("Invalid Length");

                    const part1Hex = sha256Content.substring(0, 32);
                    const part2Hex = sha256Content.substring(32, 64);
                    const input1 = BigInt('0x' + part1Hex);
                    const input2 = BigInt('0x' + part2Hex);
                    const poseidonResult = poseidon([input1, input2]);
                    const poseidonStr = F.toString(poseidonResult);

                    if (!component.properties) component.properties = [];
                    // 清理舊資料
                    component.properties = component.properties.filter(p => !p.name.startsWith('research:zkp:'));

                    component.properties.push({ "name": "research:zkp:hash:poseidon", "value": poseidonStr });
                    component.properties.push({ "name": "research:zkp:witness:part1", "value": input1.toString() });
                    component.properties.push({ "name": "research:zkp:witness:part2", "value": input2.toString() });

                    count++;
                } catch (e) {
                    console.error(`[!] Error processing ${component.name}: ${e.message}`);
                }
            } else {
                console.warn(`[!] No hash found for library: ${component.name} (checked SBOM and requirements.txt)`);
            }
        }
    }

    fs.writeFileSync(argv.output, JSON.stringify(sbom, null, 2));
    console.log(`[+] Success! Processed ${count} libraries.`);
    console.log(`[+] Output saved to: ${argv.output}`);
}

main().catch(err => { console.error(err); process.exit(1); });