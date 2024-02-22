import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress } from "ethers/lib/utils";
import {ecdh, chacha20_poly1305_seal}  from "@solar-republic/neutrino";
import {bytes, bytes_to_base64, json_to_bytes, sha256, concat, text_to_bytes, base64_to_bytes} from '@blake.regalia/belt';


export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x3879E146140b627a5C858a08e507B171D9E43139' //EVM gateway contract address
    // create the abi interface and encode the function data
    const abi = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"InvalidBytesLength","type":"error"},{"inputs":[],"name":"InvalidInitialization","type":"error"},{"inputs":[],"name":"InvalidPacketSignature","type":"error"},{"inputs":[],"name":"InvalidPayloadHash","type":"error"},{"inputs":[],"name":"InvalidSignature","type":"error"},{"inputs":[],"name":"InvalidSignatureLength","type":"error"},{"inputs":[],"name":"NotInitializing","type":"error"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"OwnableInvalidOwner","type":"error"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"OwnableUnauthorizedAccount","type":"error"},{"inputs":[],"name":"PaidRequestFeeTooLow","type":"error"},{"inputs":[],"name":"TaskAlreadyCompleted","type":"error"},{"inputs":[],"name":"TooManyVRFRandomWordsRequested","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint64","name":"version","type":"uint64"}],"name":"Initialized","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"taskId","type":"uint256"},{"indexed":false,"internalType":"bool","name":"callbackSuccessful","type":"bool"}],"name":"TaskCompleted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"task_id","type":"uint256"},{"indexed":false,"internalType":"string","name":"source_network","type":"string"},{"indexed":false,"internalType":"address","name":"user_address","type":"address"},{"indexed":false,"internalType":"string","name":"routing_info","type":"string"},{"indexed":false,"internalType":"bytes32","name":"payload_hash","type":"bytes32"},{"components":[{"internalType":"bytes","name":"user_key","type":"bytes"},{"internalType":"bytes","name":"user_pubkey","type":"bytes"},{"internalType":"string","name":"routing_code_hash","type":"string"},{"internalType":"string","name":"task_destination_network","type":"string"},{"internalType":"string","name":"handle","type":"string"},{"internalType":"bytes12","name":"nonce","type":"bytes12"},{"internalType":"uint32","name":"callback_gas_limit","type":"uint32"},{"internalType":"bytes","name":"payload","type":"bytes"},{"internalType":"bytes","name":"payload_signature","type":"bytes"}],"indexed":false,"internalType":"struct Gateway.ExecutionInfo","name":"info","type":"tuple"}],"name":"logNewTask","type":"event"},{"inputs":[{"internalType":"uint256","name":"_newTaskId","type":"uint256"}],"name":"increaseTaskId","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"payoutBalance","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_taskId","type":"uint256"},{"internalType":"string","name":"_sourceNetwork","type":"string"},{"components":[{"internalType":"bytes32","name":"payload_hash","type":"bytes32"},{"internalType":"bytes32","name":"packet_hash","type":"bytes32"},{"internalType":"bytes20","name":"callback_address","type":"bytes20"},{"internalType":"bytes4","name":"callback_selector","type":"bytes4"},{"internalType":"bytes4","name":"callback_gas_limit","type":"bytes4"},{"internalType":"bytes","name":"packet_signature","type":"bytes"},{"internalType":"bytes","name":"result","type":"bytes"}],"internalType":"struct Gateway.PostExecutionInfo","name":"_info","type":"tuple"}],"name":"postExecution","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint32","name":"_numWords","type":"uint32"},{"internalType":"uint32","name":"_callbackGasLimit","type":"uint32"}],"name":"requestRandomness","outputs":[{"internalType":"uint256","name":"requestId","type":"uint256"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"_payloadHash","type":"bytes32"},{"internalType":"address","name":"_userAddress","type":"address"},{"internalType":"string","name":"_routingInfo","type":"string"},{"components":[{"internalType":"bytes","name":"user_key","type":"bytes"},{"internalType":"bytes","name":"user_pubkey","type":"bytes"},{"internalType":"string","name":"routing_code_hash","type":"string"},{"internalType":"string","name":"task_destination_network","type":"string"},{"internalType":"string","name":"handle","type":"string"},{"internalType":"bytes12","name":"nonce","type":"bytes12"},{"internalType":"uint32","name":"callback_gas_limit","type":"uint32"},{"internalType":"bytes","name":"payload","type":"bytes"},{"internalType":"bytes","name":"payload_signature","type":"bytes"}],"internalType":"struct Gateway.ExecutionInfo","name":"_info","type":"tuple"}],"name":"send","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"taskId","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"tasks","outputs":[{"internalType":"bytes31","name":"payload_hash_reduced","type":"bytes31"},{"internalType":"bool","name":"completed","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"upgradeHandler","outputs":[],"stateMutability":"nonpayable","type":"function"}]
    const iface= new ethers.utils.Interface( abi )

    const routing_contract = "secret1fxs74g8tltrngq3utldtxu9yys5tje8dzdvghr" //the contract you want to call in secret
    const routing_code_hash = "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d" //its codehash

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()

        await (window as any).ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: '0xAA36A7' }], // chainId must be in hexadecimal numbers
        });

        // @ts-ignore
        const provider = new ethers.providers.Web3Provider(window.ethereum);
        const [myAddress] = await provider.send("eth_requestAccounts", []);
        
        //Generating ephemeral keys
        const wallet = ethers.Wallet.createRandom();
        const userPrivateKeyBytes = arrayify(wallet.privateKey);
        const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
        const userPublicKeyBytes = arrayify(userPublicKey)

        //Gateway Encryption key for ChaCha20-Poly1305 Payload encryption
        const gatewayPublicKey = "A20KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3";
        const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);

        //create the sharedKey via ECDH
        const sharedKey = await sha256(ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes));

        const numWords = document.querySelector<HTMLFormElement>('#input1')?.value;
        const callback_gas_limit = document.querySelector<HTMLFormElement>('#input2')?.value;
        
        const data = JSON.stringify({
            numWords: Number(numWords)
        })

        const callbackAddress = publicClientAddress.toLowerCase();
        //This is an empty callback for the sake of having a callback in the sample code.
        //Here, you would put your callback selector for you contract in. 
        const callbackSelector = iface.getSighash(iface.getFunction("upgradeHandler"))
        const callbackGasLimit = Number(callback_gas_limit)

        //the function name of the function that is called on the private contract
        const handle = "request_random"

        //payload data that are going to be encrypted
        const payload = {
            data: data,
            routing_info: routing_contract,
            routing_code_hash: routing_code_hash,
            user_address: myAddress,
            user_key: bytes_to_base64(userPublicKeyBytes),
            callback_address: bytes_to_base64(arrayify(callbackAddress)),
            callback_selector: bytes_to_base64(arrayify(callbackSelector)),
            callback_gas_limit: callbackGasLimit,
        }

        //build a Json of the payload
        const payloadJson = JSON.stringify(payload);
        const plaintext = json_to_bytes(payload);

        //generate a nonce for ChaCha20-Poly1305 encryption 
        //DO NOT skip this, stream cipher encryptions are only secure with a random nonce!
        const nonce = crypto.getRandomValues(bytes(12));

        //Encrypt the payload using ChachaPoly1305 and concat the ciphertext+tag to fit the Rust ChaChaPoly1305 requirements
        const [ciphertextClient, tagClient] = chacha20_poly1305_seal(sharedKey, nonce, plaintext);
        const ciphertext = concat([ciphertextClient, tagClient]);
    
        //get Metamask to sign the payloadhash with personal_sign
        const ciphertextHash = keccak256(ciphertext)

        //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
        const payloadHash = keccak256(concat([
            text_to_bytes("\x19Ethereum Signed Message:\n32"),
            arrayify(ciphertextHash),
        ]))

        //this is what we provide to metamask
        const msgParams = ciphertextHash;
        const from = myAddress;
        const params = [from, msgParams];
        const method = 'personal_sign';
        console.log(`Payload Hash: ${payloadHash}`)

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${payloadJson}</p>

        <h2>TNLS Payload</h2>
        <p>${bytes_to_base64(ciphertext)}</p>

        <h2>Payload Hash</h2>
        <p>${payloadHash}<p>
        `

        const payloadSignature = await provider.send(method, params)
        console.log(`Payload Signature: ${payloadSignature}`)

        const user_pubkey = recoverPublicKey(payloadHash, payloadSignature)
        console.log(`Recovered public key: ${user_pubkey}`)
        console.log(`Verify this matches the user address: ${computeAddress(user_pubkey)}`)

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${payloadJson}</p>

        <h2>TNLS Payload</h2>
        <p>${bytes_to_base64(ciphertext)}</p>

        <h2>Payload Hash</h2>
        <p>${payloadHash}<p>

        <h2>Payload Signature</h2>
        <p>${payloadSignature}<p>
        `
        // function data to be abi encoded
        const _userAddress = myAddress
        const _routingInfo = routing_contract
        const _payloadHash = payloadHash
        const _info = {
            user_key: hexlify(userPublicKeyBytes),
            user_pubkey: user_pubkey, 
            routing_code_hash: routing_code_hash,
            task_destination_network: "pulsar-3",  //Destination for the task, here: pulsar-3 testnet
            handle: handle,
            nonce: hexlify(nonce),
            payload: hexlify(ciphertext),
            payload_signature: payloadSignature,
            callback_gas_limit: Number(callbackGasLimit)
        }
                        
 
        console.log(`_userAddress: ${_userAddress}
        _routingInfo: ${_routingInfo} 
        _payloadHash: ${_payloadHash} 
        _info: ${JSON.stringify(_info)}
        _callbackAddress: ${callbackAddress},
        _callbackSelector: ${callbackSelector} ,
        _callbackGasLimit: ${callbackGasLimit}`)

        const functionData = iface.encodeFunctionData("send",
            [
                _payloadHash,
                _userAddress,
                _routingInfo,
                _info,
            ]
        )
        

        //Then calculate how much gas you have to pay for the callback
        //Forumla: callbackGasLimit*block.basefee.
        //Use an appropriate overhead for the transaction, 1,5x = 3/2 is recommended since gasPrice fluctuates.

        const gasFee = await provider.getGasPrice();
        const amountOfGas = gasFee.mul(callbackGasLimit).mul(3).div(2);

        const tx_params = [
            {
                gas: hexlify(150000),
                to: publicClientAddress,
                from: myAddress,
                value: hexlify(amountOfGas), // send that extra amount of gas in to pay for the Callback Gas Limit that you set
                data: functionData, 
            },
          ];

        const txHash = await provider.send("eth_sendTransaction", tx_params);

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${payloadJson}</p>

        <h2>TNLS Payload</h2>
        <p>${bytes_to_base64(ciphertext)}</p>

        <h2>Payload Hash</h2>
        <p>${payloadHash}<p>

        <h2>Payload Signature</h2>
        <p>${payloadSignature}<p>

        <h2>Other Info</h2>
        <p>

        <b>Public key used during encryption:</b> ${userPublicKey} <br>
        <b>Nonce used during encryption:</b> ${nonce} <br>

        </p>

        <h2>Transaction Parameters</h2>
        <p><b>Tx Hash: </b><a href="https://sepolia.etherscan.io/tx/${txHash}" target="_blank">${txHash}</a></p>
        <p><b>Gateway Address (to check the postExecution callback) </b><a href="https://sepolia.etherscan.io/address/${publicClientAddress}" target="_blank">${publicClientAddress}</a></p>
        <p style="font-size: 0.8em;">${JSON.stringify(tx_params)}</p>
        `
    })
}
