import {ecdh, chacha20_poly1305_seal}  from "@solar-republic/neutrino";
import {bytes_to_base64, json_to_bytes, sha256, concat, base64_to_bytes} from '@blake.regalia/belt';
import { Connection} from '@solana/web3.js';
import { AnchorProvider, Program, web3 } from '@coral-xyz/anchor';
import idl from './solana_gateway.json';
import { Buffer } from "buffer";
import { keccak256 } from "js-sha3";
import { SigningKey, ethers } from "ethers";

export function setupSubmit(element: HTMLButtonElement) {

    // create the abi interface and encode the function data

    const task_destination_network = "pulsar-3";

    //Gateway Encryption key for ChaCha20-Poly1305 Payload encryption
    const gatewayPublicKey = "AvDD5gDH97PEg96+j5ioOcLZMjDY+Fezwpjch2PCCK/N";
    const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);

    const routing_contract = "secret15n9rw7leh9zc64uqpfxqz2ap3uz4r90e0uz3y3" //the contract you want to call in secret
    const routing_code_hash = "931a6fa540446ca028955603fa4b924790cd3c65b3893196dc686de42b833f9c" //its codehash

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()
        
        const network = "https://api.devnet.solana.com";
        const connection = new Connection(network, 'processed');
        // Check for Phantom wallet
        const getProvider = () => {
            if ("solana" in window) {
                const provider = window.solana as any;
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
          
        const anchorProvider = new AnchorProvider(connection, wallet, { preflightCommitment: "processed" });
        //@ts-ignore
        const program = new Program(idl, anchorProvider);
        
        
        //Generating ephemeral keys
        const walletEpheremal = ethers.Wallet.createRandom();
        const userPrivateKeyBytes = Buffer.from(walletEpheremal.privateKey.slice(2), "hex");
        const userPublicKey: string = new SigningKey(walletEpheremal.privateKey).compressedPublicKey;
        const userPublicKeyBytes = Buffer.from(userPublicKey.slice(2), "hex")

        const sharedKey = await sha256(ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes));

        const numWords = document.querySelector<HTMLFormElement>('#input1')?.value;
        const callback_gas_limit = document.querySelector<HTMLFormElement>('#input2')?.value;
          
          const data = JSON.stringify({
              numWords: Number(numWords)
          })
  
          const callbackAddress = "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN";
          //This is an empty callback for the sake of having a callback in the sample code.
          //Here, you would put your callback selector for you contract in. 
          const functionIdenfitfier = "0x00"
          const callbackSelector = "0x00"
          
          const callbackGasLimit = Number(callback_gas_limit)
  
          //the function name of the function that is called on the private contract
          const handle = "request_random"
  
          //payload data that are going to be encrypted
          const payload = { 
              data: data,
              routing_info: routing_contract,
              routing_code_hash: routing_code_hash,
              user_address: provider.publicKey.toBase58(),
              user_key: Buffer.from(userPublicKeyBytes).toString('base64'),
              callback_address: callbackAddress,
              callback_selector: Buffer.from(callbackSelector).toString('base64'),
              callback_gas_limit: callbackGasLimit,
          }
         
          //build a Json of the payload
          const plaintext = json_to_bytes(payload)
  
          //generate a nonce for ChaCha20-Poly1305 encryption 
          //DO NOT skip this, stream cipher encryptions are only secure with a random nonce!
          const nonce = crypto.getRandomValues(new Uint8Array(12));
  
          //Encrypt the payload using ChachaPoly1305 and concat the ciphertext+tag to fit the Rust ChaChaPoly1305 requirements
          const [ciphertextClient, tagClient] = chacha20_poly1305_seal(sharedKey, nonce, plaintext);
          const ciphertext = concat([ciphertextClient, tagClient]);
      
          //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
          const payloadHash = Buffer.from(keccak256.arrayBuffer(ciphertext));
          
          const payloadHashBase64 = Buffer.from(payloadHash).toString('base64');
          console.log(payloadHashBase64);
  
          // Sign the message

          const payloadSignature = await provider.signMessage(Buffer.from(payloadHashBase64));

          const executionInfo = {
            userKey: Buffer.from(userPublicKeyBytes), // Replace with actual user key
            userPubkey: payloadSignature.publicKey.toBuffer(), // Replace with actual user pubkey
            routingCodeHash: routing_code_hash,
            taskDestinationNetwork: task_destination_network,
            handle: handle,
            nonce: Buffer.from(nonce), // Replace with actual nonce
            callbackGasLimit: callback_gas_limit, // Replace with actual gas limit
            payload: Buffer.from(ciphertext), // Ensure payload is a Buffer
            payloadSignature: payloadSignature.signature, // Replace with actual payload signature, as a Buffer
        };

        // Derive the PDA / Programm Derived Address
        const [pda, bump] = web3.PublicKey.findProgramAddressSync(
            [Buffer.from("gateway_state")],
            program.programId
        );
        
        const { blockhash } = await connection.getRecentBlockhash('finalized');
        const tx2 = await program.methods.send(
            provider.publicKey,
            routing_contract,
            executionInfo,
            bump
        )
        .accounts({
            gatewayState: pda,
            user: provider.publicKey,
            systemProgram: web3.SystemProgram.programId,
            })
        .transaction(); 
  
        // Set the recent blockhash
        tx2.recentBlockhash = blockhash;
        tx2.feePayer = provider.publicKey;

        // Sign the transaction using Phantom wallet
        const signedTx = await provider.signTransaction(tx2);
        
        // Send the signed transaction
        const signature = await connection.sendRawTransaction(signedTx.serialize());

        const strategy = {
            signature: signature, // Your transaction signature
            // Add any additional parameters for the strategy if needed
        };
        await connection.confirmTransaction(strategy as any);
        
        console.log('Final result after rpc:', tx2);
  
        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${bytes_to_base64(plaintext)}</p>

        <h2>Secretpath Payload</h2>
        <p>${bytes_to_base64(ciphertext)}</p>

        <h2>Payload Hash</h2>
        <p>${bytes_to_base64(payloadHash)}<p>
        `

        console.log(`Payload Signature: ${payloadSignature}`)
        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${bytes_to_base64(plaintext)}</p>

        <h2>TNLS Payload</h2>
        <p>${bytes_to_base64(ciphertext)}</p>

        <h2>Payload Hash</h2>
        <p>${bytes_to_base64(payloadHash)}<p>

        <h2>Payload Signature</h2>
        <p>${bytes_to_base64(payloadSignature.signature)}<p>
        ` 
 
        console.log(`_userAddress: ${provider.publicKey.toBase58()}
        _routingInfo: ${routing_contract} 
        _payloadHash: ${payloadHash} 
        _info: ${JSON.stringify(executionInfo)}
        _callbackAddress: ${callbackAddress},
        _callbackSelector: ${callbackSelector} ,
        _callbackGasLimit: ${callbackGasLimit}`)

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${JSON.stringify(payload)}</p>

        <h2>TNLS Payload</h2>
        <p>${bytes_to_base64(ciphertext)}</p>

        <h2>Payload Hash</h2>
        <p>${bytes_to_base64(payloadHash)}<p>

        <h2>Payload Signature</h2>
        <p>${bytes_to_base64(payloadSignature.signature)}<p>

        <h2>Other Info</h2>
        <p>

        <b>Public key used during encryption:</b> ${bytes_to_base64(userPublicKeyBytes)} <br>
        <b>Nonce used during encryption:</b> ${bytes_to_base64(nonce)} <br>

        </p>

        <h2>Transaction Parameters</h2>
        <p><b>Tx Hash: </b><a href="https://solscan.io/tx/${signature}?cluster=devnet" target="_blank">${signature}</a></p>
        <p><b>Gateway Address (to check the postExecution callback) </b><a href="https://solscan.io/account/${program.programId}?cluster=devnet" target="_blank">${program.programId}</a></p>
        `
    })
}
