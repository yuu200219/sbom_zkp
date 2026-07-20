import fs from 'fs';
import path from 'path';
import { SbomProcessor } from './processor.js';

function runTest() {
    const sbomPath = path.join(process.cwd(), 'uploads', 'poetry.lock_sbom.json');
    if (!fs.existsSync(sbomPath)) {
        console.error(`Sample SBOM file not found at: ${sbomPath}`);
        return;
    }

    console.log(`Loading sample SBOM from ${sbomPath}...`);
    const rawSbom = JSON.parse(fs.readFileSync(sbomPath, 'utf-8'));

    const processor = new SbomProcessor();
    console.log(`Running preorderTraversal...`);
    processor.preorderTraversal(rawSbom, 'Test-Project', '1.0.0');
}

runTest();
