"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
// client-test.ts
var axios_1 = require("axios");
var fs_1 = require("fs");
var path_1 = require("path");
var form_data_1 = require("form-data");
function testGenerateAndProve(filePath, artifactId) {
    return __awaiter(this, void 0, void 0, function () {
        var form, response, error_1;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    // 檢查檔案是否存在
                    if (!fs_1.default.existsSync(filePath)) {
                        console.error("\u274C \u627E\u4E0D\u5230\u6A94\u6848: ".concat(filePath));
                        return [2 /*return*/];
                    }
                    console.log("\uD83D\uDE80 [Client] \u6E96\u5099\u4E0A\u50B3\u4E26\u8B49\u660E: ".concat(path_1.default.basename(filePath)));
                    form = new form_data_1.default();
                    // 'file' 必須對應到 node-api 中 upload.single('file') 的名稱
                    form.append('file', fs_1.default.createReadStream(filePath));
                    form.append('artifactId', artifactId);
                    _a.label = 1;
                case 1:
                    _a.trys.push([1, 3, , 4]);
                    console.time('Total-Process-Time');
                    return [4 /*yield*/, axios_1.default.post('http://localhost:3000/api/generate-and-prove', form, {
                            headers: __assign({}, form.getHeaders()),
                            maxContentLength: Infinity,
                            maxBodyLength: Infinity,
                        })];
                case 2:
                    response = _a.sent();
                    console.timeEnd('Total-Process-Time');
                    // 3. 處理結果
                    console.log("✅ [Client] 成功拿到結果！");
                    console.log("Merkle Root:", response.data.merkleRoot);
                    console.log("ZK Proof 狀態: proved 且上傳至 IPFS");
                    console.log("IPFS CID:", response.data.ipfs.cid);
                    console.log("處理時間 (ms):", response.data.time);
                    return [3 /*break*/, 4];
                case 3:
                    error_1 = _a.sent();
                    if (error_1.response) {
                        console.error("❌ 伺服器錯誤:", error_1.response.data);
                    }
                    else {
                        console.error("❌ 請求失敗:", error_1.message);
                    }
                    return [3 /*break*/, 4];
                case 4: return [2 /*return*/];
            }
        });
    });
}
// --- 測試區 ---
// 測試案例 A: Python 需求檔
var pythonManifest = '../../../sbom-risc0/sbom/flask_server/requirements_a.txt';
var nodeLockfile = '../package-lock.json';
// testGenerateAndProve(pythonManifest, "python-app-v1");
testGenerateAndProve(nodeLockfile, "node-app-v1");
// 測試案例 B: Node.js Lockfile (如果有的話)
// const nodeLockfile = './package-lock.json';
// testGenerateAndProve(nodeLockfile, "node-app-v1");
