import { ecdh, chacha20_poly1305_seal } from "@solar-republic/neutrino";
import {
  bytes_to_base64,
  json_to_bytes,
  sha256,
  concat,
  base64_to_bytes,
} from "@blake.regalia/belt";
import { Connection } from "@solana/web3.js";
import { AnchorProvider, Program, web3 } from "@coral-xyz/anchor";
import idl from "./solana_gateway.json";
import { Buffer } from "buffer";
import { keccak256 } from "js-sha3";
import { SigningKey, ethers } from "ethers";

export function setupSubmit(element: HTMLButtonElement) {
  // create the abi interface and encode the function data

  const task_destination_network = "pulsar-3";

  // Gateway Encryption key for ChaCha20-Poly1305 Payload encryption
  const gatewayPublicKey = "A20KrD7xDmkFXpNMqJn1CLpRaDLcdKpO1NdBBS7VpWh3";
  const gatewayPublicKeyBytes = base64_to_bytes(gatewayPublicKey);

  const routing_contract =
    "secret1cknezaxnzfys2w8lyyrr7fed9wxejvgq7alhqx"; // the contract you want to call in Secret Network
  const routing_code_hash =
    "0b9395a7550b49d2b8ed73497fd2ebaf896c48950c4186e491ded6d22e58b8c3"; // its codehash

  element.addEventListener("click", async function (event: Event) {
    event.preventDefault();

    const network = "https://api.devnet.solana.com";
    const connection = new Connection(network, "processed");

    // Check for any Solana wallet
    const getProvider = () => {
      if ("solana" in window) {
        const provider = window.solana as any;
        return provider;
      }
      window.open("https://docs.solana.com/wallet-guide", "_blank");
    };

    const provider = getProvider();
    if (!provider) {
      console.error("Solana wallet not found");
      return;
    } else {
      await provider.connect(); // Connect to the wallet
    }

    const wallet = {
      publicKey: provider.publicKey,
      signTransaction: provider.signTransaction
        ? provider.signTransaction.bind(provider)
        : undefined,
      signAllTransactions: provider.signAllTransactions
        ? provider.signAllTransactions.bind(provider)
        : undefined,
    };

    const anchorProvider = new AnchorProvider(connection, wallet, {
      preflightCommitment: "processed",
    });
    //@ts-ignore
    const program = new Program(idl, anchorProvider);

    // Generating ephemeral keys
    const walletEpheremal = ethers.Wallet.createRandom();
    const userPrivateKeyBytes = Buffer.from(
      walletEpheremal.privateKey.slice(2),
      "hex"
    );
    const userPublicKey: string = new SigningKey(walletEpheremal.privateKey)
      .compressedPublicKey;
    const userPublicKeyBytes = Buffer.from(userPublicKey.slice(2), "hex");

    const sharedKey = await sha256(
      ecdh(userPrivateKeyBytes, gatewayPublicKeyBytes)
    );

    const numWordsInput = document.querySelector<HTMLInputElement>("#input1")
      ?.value;
    const callback_gas_limit =
      document.querySelector<HTMLInputElement>("#input2")?.value;

    // Add check for numWords not exceeding 18
    const numWords = Number(numWordsInput);
    if (numWords > 18) {
      alert("numWords cannot be greater than 18");
      return;
    }

    const data = JSON.stringify({
      numWords: numWords,
    });

    // Derive the Gateway PDA / Program Derived Address
    const [gateway_pda, gateway_bump] =
      web3.PublicKey.findProgramAddressSync(
        [Buffer.from("gateway_state")],
        program.programId
      );
    // Derive the Tasks PDA / Program Derived Address
    const [tasks_pda, task_bump] = web3.PublicKey.findProgramAddressSync(
      [Buffer.from("task_state")],
      program.programId
    );

    // Include some address as a test (not needed here, you can add whatever you need for your dApp)
    const testAddress1 = new web3.PublicKey(
      "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN"
    );
    const testAddress2 = new web3.PublicKey(
      "GPuidhXoR6PQ5skXEdrnJehYbffCXfLDf7pcnxH2EW7P"
    );
    const callbackAddress = Buffer.concat([
      testAddress1.toBuffer(),
      testAddress2.toBuffer(),
    ]).toString("base64");

    // This is an empty callback for the sake of having a callback in the sample code.
    // Here, you would put your callback selector for you contract in.
    // 8 bytes of the function Identifier = CallbackTest in the SecretPath Solana Contract
    const functionIdentifier = [196, 61, 185, 224, 30, 229, 25, 52];
    const programId = program.programId.toBuffer();

    // Callback Selector is ProgramId (32 bytes) + function identifier (8 bytes) concatenated
    const callbackSelector = Buffer.concat([
      programId,
      Buffer.from(functionIdentifier),
    ]);

    const callbackGasLimit = Number(callback_gas_limit);

    // The function name of the function that is called on the private contract
    const handle = "request_random";

    // Payload data that are going to be encrypted
    const payload = {
      data: data,
      routing_info: routing_contract,
      routing_code_hash: routing_code_hash,
      user_address: provider.publicKey.toBase58(),
      user_key: Buffer.from(userPublicKeyBytes).toString("base64"),
      callback_address: callbackAddress,
      callback_selector: Buffer.from(callbackSelector).toString("base64"),
      callback_gas_limit: callbackGasLimit,
    };

    // Build a JSON of the payload
    const plaintext = json_to_bytes(payload);

    // Generate a nonce for ChaCha20-Poly1305 encryption
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt the payload using ChachaPoly1305 and concatenate the ciphertext + tag
    const [ciphertextClient, tagClient] = chacha20_poly1305_seal(
      sharedKey,
      nonce,
      plaintext
    );
    const ciphertext = concat([ciphertextClient, tagClient]);

    // This is the payload hash
    const payloadHash = Buffer.from(keccak256.arrayBuffer(ciphertext));

    // Display raw payload and encrypted payload
    document.querySelector<HTMLDivElement>("#preview")!.innerHTML = `
      <h2>Raw Payload</h2>
      <p>${JSON.stringify(payload)}</p>

      <h2>Secretpath Payload</h2>
      <p>${bytes_to_base64(ciphertext)}</p>

      <h2>Payload Hash</h2>
      <p>${bytes_to_base64(payloadHash)}</p>
    `;

    // Sign the message, which is the Base64 String of the Payload Hash
    const payloadHashBase64 = Buffer.from(payloadHash.toString("base64"));
    const payloadSignature = await provider.signMessage(payloadHashBase64);

    document.querySelector<HTMLDivElement>("#preview")!.innerHTML += `
      <h2>Payload Signature</h2>
      <p>${bytes_to_base64(payloadSignature.signature)}</p>
    `;

    const executionInfo = {
      userKey: Buffer.from(userPublicKeyBytes),
      userPubkey: payloadSignature.publicKey.toBuffer(),
      routingCodeHash: routing_code_hash,
      taskDestinationNetwork: task_destination_network,
      handle: handle,
      nonce: Buffer.from(nonce),
      callbackGasLimit: callbackGasLimit,
      payload: Buffer.from(ciphertext),
      payloadSignature: payloadSignature.signature,
    };

    // Get the latest blockhash
    const { blockhash } = await connection.getLatestBlockhash("confirmed");

    // Construct the transaction
    const tx = await program.methods
      .send(provider.publicKey, routing_contract, executionInfo)
      .accounts({
        gatewayState: gateway_pda,
        taskState: tasks_pda,
        user: provider.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .transaction();

    // Set the recent blockhash and fee payer
    tx.recentBlockhash = blockhash;
    tx.feePayer = provider.publicKey;

    // Sign the transaction using the wallet
    const signedTx = await provider.signTransaction(tx);

    // Send the signed transaction
    const signature = await connection.sendRawTransaction(signedTx.serialize());

    const strategy = {
      signature: signature,
    };

    await connection.confirmTransaction(strategy as any);

    console.log("Final result after RPC:", tx);

    console.log(`_userAddress: ${provider.publicKey.toBase58()}
        _routingInfo: ${routing_contract}
        _payloadHash: ${bytes_to_base64(payloadHash)}
        _info: ${JSON.stringify(executionInfo)}
        _callbackAddress: ${callbackAddress}
        _callbackSelector: ${bytes_to_base64(callbackSelector)}
        _callbackGasLimit: ${callbackGasLimit}`);

    document.querySelector<HTMLDivElement>("#preview")!.innerHTML += `
      <h2>Other Info</h2>
      <p>
        <b>Public key used during encryption:</b> ${bytes_to_base64(
          userPublicKeyBytes
        )}<br>
        <b>Nonce used during encryption:</b> ${bytes_to_base64(nonce)}<br>
      </p>

      <h2>Transaction Parameters</h2>
      <p><b>Tx Hash: </b><a href="https://solscan.io/tx/${signature}?cluster=devnet" target="_blank">${signature}</a></p>
      <p><b>Gateway Address (to check the postExecution callback): </b><a href="https://solscan.io/account/${
        program.programId
      }?cluster=devnet" target="_blank">${program.programId}</a></p>
    `;
  });
}
