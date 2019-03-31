'use strict';

const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const createHash = (input) => {
    const hash = crypto.createHash('sha256');
    hash.update(input);

    return hash.digest();
}

const getBasicKeys = (hash) => {
    let output = new Uint32Array(8);

    output[0] = hash.readInt32LE(0);
    output[1] = hash.readInt32LE(4);
    output[2] = hash.readInt32LE(8);
    output[3] = hash.readInt32LE(12);
    output[4] = hash.readInt32LE(16);
    output[5] = hash.readInt32LE(20);
    output[6] = hash.readInt32LE(24);
    output[7] = hash.readInt32LE(28);

    return output;
}

const xorThis = (dest, additive, value) => {
    let currentVal = dest.readInt32LE(additive);
    let newVal = currentVal ^ value;
    dest.writeInt32LE(newVal, additive);
}

const crypt = (filename, secret) => {
    // READ FILE
    fs.readFile(filename, (err, data) => {
        if (err) throw err;
        console.log("Read File!\n");

        let keys = getBasicKeys(createHash(secret));

        // 4 byte alignement
        let align = 0;
        while (((data.length - align) % 4) != 0)
            align++;

        // goes through buffer data from file and
        // crypts every 4 bytes with key from hash
        // then each time the key is increased
        let currentKey = -1;
        for (let i = 0; i < data.length - align; i += 4) {
            currentKey++;
            if (currentKey > 7)
                currentKey = 0;
            xorThis(data, i, keys[currentKey]);
        }
        for (let i = 0; i < data.length; i++)
            data[i] = ~data[i];

        rl.question("Are you sure you want to overwrite this file? (y/n) ", (answer) => {
            if(answer == "y")
            {
                fs.writeFileSync(filename, data);
                rl.close();
            }
            else {
                rl.close();
            }
        });
    });
}

var main = function () {
    let file = "";
    rl.question("What is the filename you want to crypt? ", (f) => {
        file = f;
        let secret = "";
        rl.question("Enter a password: ", (pass) => {
            secret = pass;
            rl.pause();
            crypt(file, secret);
        });
    });
}
if (require.main === module) {
    main();
}