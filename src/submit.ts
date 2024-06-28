import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress } from "ethers/lib/utils";
import {ecdh, chacha20_poly1305_seal}  from "@solar-republic/neutrino";
import {bytes, bytes_to_base64, json_to_bytes, sha256, concat, text_to_bytes, base64_to_bytes} from '@blake.regalia/belt';
import { Connection, PublicKey, Keypair, Transaction, SystemProgram } from '@solana/web3.js';
import { AnchorProvider, Program, Wallet } from '@coral-xyz/anchor';
import idl from './solana_gateway.json';


export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x3879E146140b627a5C858a08e507B171D9E43139' //EVM gateway contract address
    // create the abi interface and encode the function data

    const routing_contract = "secret1fxs74g8tltrngq3utldtxu9yys5tje8dzdvghr" //the contract you want to call in secret
    const routing_code_hash = "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d" //its codehash

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()
        
        const network = "https://api.devnet.solana.com";
        const connection = new Connection(network, 'processed');
        // Check for Phantom wallet
        const getProvider = () => {
            if ("solana" in window) {
            const provider = window.solana;
            if (provider.isPhantom) {
                return provider;
            }
            }
            window.open("https://phantom.app/", "_blank");
        };
        
        const provider = getProvider();
        if (!provider) {
            console.error("Phantom wallet not found");
        } else {
            await provider.connect(); // Connect to the wallet
        }
        const wallet = {
            publicKey: provider.publicKey,
            signTransaction: provider.signTransaction.bind(provider),
            signAllTransactions: provider.signAllTransactions.bind(provider)
        };
          
        const programId = new PublicKey(idl.address);
        const anchorProvider = new AnchorProvider(connection, wallet, { preflightCommitment: "processed" });
        const program = new Program(idl, programId, anchorProvider);
        
        
        //Generating ephemeral keys
        const walletEpheremal = ethers.Wallet.createRandom();
        const userPrivateKeyBytes = arrayify(walletEpheremal.privateKey);
        const userPublicKey: string = new SigningKey(walletEpheremal.privateKey).compressedPublicKey;
        const userPublicKeyBytes = arrayify(userPublicKey)

        //Gateway Encryption key for ChaCha20-Poly1305 Payload encryption
        const gatewayPublicKey = "A20KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3";
        const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);

        const task_destination_network = "pulsar-3"
        const routing_contract = "secret1rcpxtvaf2ccs7tgml7d25xr5n8suvdxr6w9nen" //the contract you want to call in secret
        const routing_code_hash = "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d" //its codehash
    
        const sharedKey = await sha256(ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes));

        const numWords = document.querySelector<HTMLFormElement>('#input1')?.value;
        const callback_gas_limit = document.querySelector<HTMLFormElement>('#input2')?.value;
          
          const data = JSON.stringify({
              numWords: Number(numWords)
          })
  
          const callbackAddress = "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN";
          //This is an empty callback for the sake of having a callback in the sample code.
          //Here, you would put your callback selector for you contract in. 
         //const callbackSelector = iface.getSighash(iface.getFunction("upgradeHandler"))
          const callbackSelector = "0x00"
          const callbackGasLimit = Number(callback_gas_limit)
  
          //the function name of the function that is called on the private contract
          const handle = "request_random"
  
  /*         pub data: String,
          /// Destination contract address.
          pub routing_info: Addr,
          /// Destination contract code hash.
          pub routing_code_hash: String,
          /// User public chain address.
          pub user_address: Addr,
          /// User public key from payload encryption (not their wallet public key).
          pub user_key: Binary,
          /// Callback address for the post execution message.
          pub callback_address: Binary,
          /// Callback selector for the post execution message.
          pub callback_selector: Binary,
          /// Callback gas limit for the post execution message.
          pub callback_gas_limit: u32,
          */
          //payload data that are going to be encrypted
          const payload = { 
              data: data,
              routing_info: routing_contract,
              routing_code_hash: routing_code_hash,
              user_address: provider.publicKey.toBase58(),
              user_key: Buffer.from(new Uint8Array(4)).toString('base64'),
              callback_address: callbackAddress,
              callback_selector: Buffer.from(new Uint8Array(4)).toString('base64'),
              callback_gas_limit: callbackGasLimit,
          }
         
          //build a Json of the payload
          const payloadJson = JSON.stringify(payload);
          const plaintext = Buffer.from(payloadJson);
  
          //generate a nonce for ChaCha20-Poly1305 encryption 
          //DO NOT skip this, stream cipher encryptions are only secure with a random nonce!
          const nonce = crypto.getRandomValues(new Uint8Array(12));
  
          //Encrypt the payload using ChachaPoly1305 and concat the ciphertext+tag to fit the Rust ChaChaPoly1305 requirements
          const [ciphertextClient, tagClient] = chacha20_poly1305_seal(sharedKey, nonce, plaintext);
          const ciphertext = concat([ciphertextClient, tagClient]);
      
          //get Metamask to sign the payloadhash with personal_sign
          const ciphertextHash = "test"
  
          //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
          const payloadHash = Buffer.from(getBytes(keccak256(plaintext)));
          
          const payloadBase64 = Buffer.from(payloadJson).toString('base64');
          console.log(payloadBase64);
    
          // Convert payloadBase64 to a buffer and sign it
          const payload_buffer = Buffer.from(payloadBase64);
          const keypair = (provider.wallet as any).payer as web3.Keypair;
  
          // Sign the message
         // const payload_signature = web3.sign(payload_buffer, keypair.secretKey);
  
          const executionInfo = {
            userKey: Buffer.from(new Uint8Array(4)), // Replace with actual user key
            userPubkey: Buffer.from(new Uint8Array(4)), // Replace with actual user pubkey
            routingCodeHash: routing_code_hash,
            taskDestinationNetwork: task_destination_network,
            handle: handle,
            nonce: Buffer.from(nonce), // Replace with actual nonce
            callbackGasLimit: callback_gas_limit, // Replace with actual gas limit
            payload: plaintext, // Ensure payload is a Buffer
            payloadSignature: Buffer.from("AA="), // Replace with actual payload signature, as a Buffer
        };
  
          const tx2 = await program.methods.send(
            payloadHash,
            provider.publicKey,
            routing_contract,
            executionInfo,
          )
          .accounts({
            gatewayState: gatewayState.publicKey,
            user: provider.publicKey,
            systemProgram: anchor.web3.SystemProgram.programId,
          })
          .signers([provider?.wallet.payer])
          .rpc();
  
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
        const _userAddress = provider.publicKey
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

        const gatewayState = await program.account.gatewayState.all();
        const gatewayStateAccount = gatewayState[0].publicKey; // Adjust to the correct gateway state account

        const tx = await program.rpc.send(
            _payloadHash,
            _userAddress,
            _routingInfo,
            _info,
            {
            accounts: {
                gatewayState: gatewayStateAccount,
                user: wallet.publicKey,
                systemProgram: SystemProgram.programId,
            },
            signers: []
            }
        );

  console.log("Transaction signature", tx);
        

        //Then calculate how much gas you have to pay for the callback
        //Forumla: callbackGasLimit*block.basefee.
        //Use an appropriate overhead for the transaction, 1,5x = 3/2 is recommended since gasPrice fluctuates.

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
        <p><b>Tx Hash: </b><a href="https://sepolia.etherscan.io/tx/" target="_blank">${""}</a></p>
        <p><b>Gateway Address (to check the postExecution callback) </b><a href="https://sepolia.etherscan.io/address/${publicClientAddress}" target="_blank">${publicClientAddress}</a></p>
        <p style="font-size: 0.8em;">${JSON.stringify("")}</p>
        `
    })
}
