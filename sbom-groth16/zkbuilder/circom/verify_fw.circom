pragma circom 2.2.2;
include "../node_modules/circomlib/circuits/poseidon.circom";

template VerifyFirmware() {
    signal input fw_hash[3];       // secret firmware chunk hash
    signal input manifest_hash;    // public hash
    signal output out;

    component hasher = Poseidon(3);
    for (var i = 0; i < 3; i++) {
        hasher.inputs[i] <== fw_hash[i];
    }

    out <== hasher.out;
    out === manifest_hash;  // constraint: Poseidon(fw_hash) == manifest_hash
}

component main = VerifyFirmware();
