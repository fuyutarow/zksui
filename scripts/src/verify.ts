import {
  Connection,
  Ed25519Keypair,
  fromB64,
  JsonRpcProvider,
  RawSigner,
  TransactionBlock,
} from "@mysten/sui.js";
import fs from "fs";

globalThis.fetch = fetch;

const loadLocalJSON = (filePath) => {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch (error) {
    console.error("Error loading local JSON file:", error);
    return null;
  }
};

const getKeypair = () => {
  const privatekey0x = process.env.SUI_PRIVATE_KEY as string;
  const privatekey = privatekey0x.replace(/^0x/, "");
  const privateKeyBase64 = Buffer.from(privatekey, "hex").toString("base64");
  return Ed25519Keypair.fromSecretKey(fromB64(privateKeyBase64));
};

const setupTransactionBlock = (vk_bytes, public_inputs_bytes, proof_points_bytes) => {
  const pkgID = "0xd0cb8699235e0785e6aba7b19e1065efbd359eea0ed702dc68228ecbda3de3e0"
  let txb = new TransactionBlock();
  txb.moveCall({
    target: `${pkgID}::verifier::verify_proof`,
    typeArguments: [],
    arguments: [
      txb.pure(vk_bytes, "vector<u8>"),
      txb.pure(public_inputs_bytes, "vector<u8>"),
      txb.pure(proof_points_bytes, "vector<u8>"),
    ],
  });
  return txb;
};

const main = async () => {
  const localData = loadLocalJSON('../prover/output_data.json');
  if (!localData) return;

  const { vk_bytes, public_inputs_bytes, proof_points_bytes } = localData;
  console.log({ vk_bytes, public_inputs_bytes, proof_points_bytes })

  const provider = new JsonRpcProvider(
    new Connection({
      fullnode: "https://sui-testnet.nodeinfra.com",
    }),
  );

  const signer = new RawSigner(getKeypair(), provider);
  const address = await signer.getAddress();
  console.log({ address });

  const txb = setupTransactionBlock(vk_bytes, public_inputs_bytes, proof_points_bytes);
  const dryRunResult = await signer.dryRunTransactionBlock({
    transactionBlock: txb,
  });

  console.log(dryRunResult);

  const result = await signer.signAndExecuteTransactionBlock({
    transactionBlock: txb,
  });
  console.log(result);

  console.log("hello");
};

main();
