const Json = require('./MyToken.json');
const API = require('@polkadot/api');
const Crypto = require('@polkadot/util-crypto');

const Tx = require("ethereumjs-tx").Transaction;
const Web3 = require('web3');

////////////////////////////////////////////////////////////
//const PROVIDER = 'ws://10.0.0.253:43001';
const PROVIDER = 'ws://192.168.182.129:43001';
const SENDER = "//...//01";
const GAS_LIMIT = 10000000n;
const GAS_PRICE = 100000000n;
const CONTRACT_GAS_PRICE = "0x200000";
const CONTRACT_GAS_LIMIT = "0x300000";

const test_eth_address = "0x32Df1C41804a53ffE08B162fA02A3c2bae829258";
const test_eth_privatekey = "0x0a445395ef32600863d003acfcb28de1334d943beedcf46adbdeafbaac02e911";
////////////////////////////////////////////////////////////

const test_call_input = "0xa9059cbb0000000000000000000000008eaf04151687736326c9fea17e25fc528761369300000000000000000000000000000000000000000000000000000000000000dd";

/*
 * Custom error code
enum TransactionValidationError {
    #[allow(dead_code)]
	UnknownError,
    InvalidChainId,
    InvalidSignature,
    InvalidGasLimit,
    MaxFeePerGasTooLow,
}
*/

function h160_to_evm_account(h160) {
    return '0x' + Buffer.from(h160).toString('hex');
}

function ss58_to_h160_account(keyring, address) {
    return h160_to_evm_account(keyring.decodeAddress(address, 256).slice(0, 20));
}

function h160_account_to_ss58_account_id(h160) {
    var account_id = Buffer.from("evm:");
    h160 = Buffer.from(h160.replace('0x', ''), 'hex');
    account_id = Buffer.concat([account_id, h160], account_id.length + h160.length);
    account_id = Crypto.blake2AsHex(account_id).replace('0x', '');
    return Buffer.from(account_id, 'hex');
}

function ss58_account_id_to_ss58(keyring, account_id) {
    account_id = Buffer.from(account_id, 'hex');
    return keyring.encodeAddress(account_id);
}

function ss58_to_evm_h256_address(keyring, address) {
    return ss58_account_id_to_ss58(keyring, h160_account_to_ss58_account_id(ss58_to_h160_account(keyring, address)));
}

async function transfer(provider, sender, to) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);

    var evm_h256_address;
    if (Web3.utils.isHex(to)) {
        evm_h256_address = ss58_account_id_to_ss58(keyring, h160_account_to_ss58_account_id(to));
    }
    else {
        to = keyring.addFromUri(to);
        evm_h256_address = ss58_to_evm_h256_address(keyring, to.address);
    }

    await api.tx.balances
        .transfer(evm_h256_address, 1000000000000000n)
        .signAndSend(sender, (result) => {
            if (result.dispatchError) {
                const dispatchError = result.dispatchError;
                if (dispatchError.isModule) {
                    // for module errors, we have the section indexed, lookup
                    const decoded = api.registry.findMetaError(dispatchError.asModule);
                    const { docs, name, section } = decoded;

                    console.log(`${section}.${name}: ${docs.join(' ')}`);
                } else {
                    // Other, CannotLookup, BadOrigin, no extra info
                    console.log(dispatchError.toString());
                }
            }
            else {
                if (result.status.isInBlock) {
                    console.log(`Transaction included at blockHash ${result.status.asInBlock}, transfer to ${evm_h256_address}`);
                } else if (result.status.isFinalized) {
                    console.log(`Transaction finalized at blockHash ${result.status.asFinalized}`);
                }
                else {
                    console.log(`Current status is ${result.status}`);
                }
            }
        });
}

async function create(provider, sender, init) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);

    const h160_account = ss58_to_h160_account(keyring, sender.address);
    const evm_h256_address = ss58_account_id_to_ss58(keyring, h160_account_to_ss58_account_id(h160_account));
    //const { nonce, data: balance } = await api.query.system.account(evm_h256_address);
    const unsub = await api.tx.evm.create(
        h160_account,
        init,
        0,
        GAS_LIMIT,
        GAS_PRICE,
        null,
        //BigInt(nonce.toNumber()),
        null,
        [],
    )
        .signAndSend(sender, (result) => {
            if (result.status.isInBlock) {
                console.log(`Transaction included at blockHash ${result.status.asInBlock}`);

                const events = result.events;
                if (result.dispatchError) {
                    const dispatchError = result.dispatchError;
                    if (dispatchError.isModule) {
                        // for module errors, we have the section indexed, lookup
                        const decoded = api.registry.findMetaError(dispatchError.asModule);
                        const { docs, name, section } = decoded;

                        console.log(`${section}.${name}: ${docs.join(' ')}`);
                    } else {
                        // Other, CannotLookup, BadOrigin, no extra info
                        console.log(dispatchError.toString());
                    }
                }
                else {
                    events.forEach(event => {
                        event = event.toHuman().event;
                        if (event.method == "Created") {
                            console.log(`Created Succeeded, contract address: ${event.data[0]}`);
                        }
                        else if (event.method == "CreatedFailed") {
                            console.log(`Created Failed`);
                        }
                    });
                }
            } else if (result.status.isFinalized) {
                console.log(`Transaction finalized at blockHash ${result.status.asFinalized}`);
                unsub();
            }
            else {
                console.log(`Current status is ${result.status}`);
            }
        });
}

async function _call(provider, api, keyring, sender, target, input) {
    const h160_account = ss58_to_h160_account(keyring, sender.address);

    return new Promise((resolve, reject) => {
        const unsub = api.tx.evm.call(
            h160_account,
            target,
            input,
            0,
            GAS_LIMIT,
            GAS_PRICE,
            null,
            null,
            [],
        )
            .signAndSend(sender, (result) => {
                if (result.status.isInBlock) {
                    console.log(`Transaction included at blockHash ${result.status.asInBlock}`);

                    const events = result.events;
                    if (result.dispatchError) {
                        const dispatchError = result.dispatchError;
                        if (dispatchError.isModule) {
                            // for module errors, we have the section indexed, lookup
                            const decoded = api.registry.findMetaError(dispatchError.asModule);
                            const { docs, name, section } = decoded;

                            console.log(`${section}.${name}: ${docs.join(' ')}`);
                        } else {
                            // Other, CannotLookup, BadOrigin, no extra info
                            console.log(dispatchError.toString());
                        }
                    }
                    else {
                        events.forEach(event => {
                            event = event.toHuman().event;
                            if (event.method == "Executed") {
                                console.log(`Call Succeeded, target address: ${event.data[0]}`);

                                const txHash = result.txHash.toString('hex');
                                const index = event.index;
                                resolve({ txHash, index });
                            }
                            else if (event.method == "ExecutedFailed") {
                                console.log(`Call Failed: ${event.method}`);
                            }
                        });
                    }
                } else if (result.status.isFinalized) {
                    console.log(`Transaction finalized at blockHash ${result.status.asFinalized}`);
                    //unsub();
                }
                else {
                    console.log(`Current status is ${result.status}`);
                }
            });
    });
}

async function call(provider, sender, target, input) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);

    await _call(provider, api, keyring, sender, target, input);
}

async function withdraw(provider, sender) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);
    const h160_account = ss58_to_h160_account(keyring, sender.address);

    const unsub = await api.tx.evm.withdraw(
        h160_account,
        100n,
    )
        .signAndSend(sender, (result) => {
            if (result.status.isInBlock) {
                console.log(`Transaction included at blockHash ${result.status.asInBlock}`);

                const events = result.events;
                if (result.dispatchError) {
                    const dispatchError = result.dispatchError;
                    if (dispatchError.isModule) {
                        // for module errors, we have the section indexed, lookup
                        const decoded = api.registry.findMetaError(dispatchError.asModule);
                        const { docs, name, section } = decoded;

                        console.log(`${section}.${name}: ${docs.join(' ')}`);
                    } else {
                        // Other, CannotLookup, BadOrigin, no extra info
                        console.log(dispatchError.toString());
                    }
                }
                else {
                    events.forEach(event => {
                        event = event.toHuman().event;
                        if (event.method == "ExtrinsicSuccess") {
                            console.log(`Withdraw Succeeded`);
                        }
                        else if (event.method == "ExecutedFailed") {
                            console.log("Withdraw Failed");
                        }
                    });
                }
            } else if (result.status.isFinalized) {
                console.log(`Transaction finalized at blockHash ${result.status.asFinalized}`);
                unsub();
            }
            else {
                console.log(`Current status is ${result.status}`);
            }
        });
}

function to_32bit_Hex_str(arg) {
    return Web3.utils.leftPad(arg, 64).replace("0x", "");
}

async function encode(api, method, args) {
    var encoded = await api.rpc.web3.sha3(method);
    encoded = encoded.toString('hex').substring(0, 10);
    for (var i = 0; i < args.length; i++) {
        encoded += to_32bit_Hex_str(args[i]);
    }
    return encoded;
}

function sign(rawTransaction, chain, privatekey) {
    const tx = new Tx(rawTransaction, { 'chain': chain });
    tx.sign(Buffer.from(privatekey.replace("0x", ""), 'hex'));
    var serializedTx = tx.serialize().toString('hex');
    serializedTx = "0x" + serializedTx;
    return serializedTx;
}

async function _call_contract_method(api, method, from, to, encoded, nonce, privatekey) {
    rawTransaction = {
        from: from,
        to: to,
        gasPrice: CONTRACT_GAS_PRICE,
        gasLimit: CONTRACT_GAS_LIMIT,//"0x3000",
        value: "0x0",
        data: encoded,
        nonce: Web3.utils.toHex(nonce.toNumber()),
    };

    const chain = await api.rpc.eth.chainId();
    serializedTx = sign(rawTransaction, chain.toNumber(), privatekey);

    var result = await api.rpc.eth.sendRawTransaction(serializedTx);
    setTimeout(async function () {
        result = await api.rpc.eth.getTransactionReceipt(result.toString('hex'));
        if (result.logs.toHuman().length == 0) {
            console.log(`${method}: getTransactionReceipt timeout`);
        }
        else {
            console.log(`${method} result: ${result.logs.toHuman()[0].data}`);
        }
    }, 30000);
}

async function call_contract_method_multiply(provider, sender, contract_address) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);

    const method = "multiply(uint256,uint256)";
    var encoded = await encode(api, method, [Web3.utils.toHex("6"), Web3.utils.toHex("7")]);

    const evm_h256_address = ss58_account_id_to_ss58(keyring, h160_account_to_ss58_account_id(test_eth_address));
    const { nonce, data: balance } = await api.query.system.account(evm_h256_address);

    _call_contract_method(
        api,
        method,
        test_eth_address,
        contract_address,
        encoded,
        nonce,
        test_eth_privatekey
    );
}

async function call_contract_method_transfer(provider, sender, contract_address) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);

    const method = "transfer(address,uint256)";
    const h160_account = ss58_to_h160_account(keyring, sender.address);
    var encoded = await encode(api, method, [h160_account, Web3.utils.toHex("100")]);

    const evm_h256_address = ss58_account_id_to_ss58(keyring, h160_account_to_ss58_account_id(test_eth_address));
    const { nonce, data: balance } = await api.query.system.account(evm_h256_address);

    _call_contract_method(
        api,
        method,
        test_eth_address,
        contract_address,
        encoded,
        nonce,
        test_eth_privatekey
    );
}

async function call_contract_method_getbalance(provider, sender, contract_address) {
    provider = new API.WsProvider(provider);
    var api = await API.ApiPromise.create({ provider });

    const keyring = new API.Keyring({ type: 'sr25519' });
    sender = keyring.addFromUri(sender);

    const method = "getBalance(address)";
    const h160_account = ss58_to_h160_account(keyring, sender.address);
    var encoded = await encode(api, method, [h160_account]);

    const evm_h256_address = ss58_account_id_to_ss58(keyring, h160_account_to_ss58_account_id(test_eth_address));
    const { nonce, data: balance } = await api.query.system.account(evm_h256_address);

    _call_contract_method(
        api,
        method,
        test_eth_address,
        contract_address,
        encoded,
        nonce,
        test_eth_privatekey
    );
}

(async () => {
    //await transfer(PROVIDER, SENDER, SENDER);
    //await transfer(PROVIDER, SENDER, test_eth_address);
    //await call(PROVIDER, SENDER, test_eth_address, test_call_input);
    //await withdraw(PROVIDER, SENDER);
    //await create(PROVIDER, SENDER, Json['bytecode']);

    //the contract address is from create
    var contract_address = "0x6b400b10c28ab02b6dc43ab719ddc04009f08c37";
    //await call_contract_method_multiply(PROVIDER, SENDER, contract_address);
    //await call_contract_method_transfer(PROVIDER, SENDER, contract_address);
    //await call_contract_method_getbalance(PROVIDER, SENDER, contract_address);
})();