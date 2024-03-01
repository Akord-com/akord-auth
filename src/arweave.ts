import { arrayToBase64, base64ToArray, stringToArray } from '@akord/crypto';
import Arweave from 'arweave';
import * as nodeCrypto from 'crypto';

const crypto = typeof window === 'undefined' ? <any>nodeCrypto.webcrypto : window.crypto;

const arConnectPermissions = [
  "ACCESS_ADDRESS",
  "SIGN_TRANSACTION",
  "SIGNATURE",
  "ACCESS_PUBLIC_KEY",
  "ACCESS_ALL_ADDRESSES",
  "ENCRYPT",
  "DECRYPT",
] as any[];

export enum KeyType {
  JWK = 'JWK',
  ARCONNECT = 'ARCONNECT'
}

export default class ArweaveWallet {
  keyType: KeyType;
  wallet: any;
  arweave: Arweave;

  constructor(jwk?: any) {
    this.arweave = Arweave.init({
      host: 'arweave.net',
      port: 443,
      protocol: 'https'
    });
    if (jwk) {
      this.keyType = KeyType.JWK
      this.wallet = jwk
    } else if (window.arweaveWallet) {
      this.keyType = KeyType.ARCONNECT
      this.wallet = window.arweaveWallet
    } else {
      throw new Error("Cannot find the wallet.")
    }
  }
  signingPrivateKeyRaw(): Promise<Uint8Array> {
    throw new Error('Method not implemented.');
  }
  signingPrivateKey(): Promise<string> {
    throw new Error('Method not implemented.');
  }

  async encrypt(input: Uint8Array) {
    const string = arrayToBase64(input);
    const array = new Uint8Array(256);
    const keyBuf = crypto.getRandomValues(array);
    const encryptedData = await Arweave.crypto.encrypt(stringToArray(string), keyBuf);
    const publicKey = await this.publicKeyRaw();
    const encryptedKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      keyBuf
    );
    const buffer = Arweave.utils.concatBuffers([encryptedKey, encryptedData]);
    return arrayToBase64(buffer);
  }

  async encryptToPublicKey(input: Uint8Array, publicKey: CryptoKey) {
    const string = arrayToBase64(input);
    const array = new Uint8Array(256);
    const keyBuf = crypto.getRandomValues(array);
    const encryptedData = await Arweave.crypto.encrypt(stringToArray(string), keyBuf);
    const encryptedKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      keyBuf
    );
    const buffer = Arweave.utils.concatBuffers([encryptedKey, encryptedData]);
    return arrayToBase64(buffer);
  }

  async decrypt(input: string) {
    const key = await importRSACryptoKey(this.wallet);
    const data = base64ToArray(input);
    const encryptedKey = new Uint8Array(
      new Uint8Array(Object.values(data)).slice(0, 512)
    )
    const encryptedData = new Uint8Array(
      new Uint8Array(Object.values(data)).slice(512)
    );

    const symmetricKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      key,
      encryptedKey
    );

    const res = await this.arweave.crypto.decrypt(
      encryptedData,
      new Uint8Array(symmetricKey)
    );
    return base64ToArray(this.arweave.utils.bufferToString(res).split(null)[0]);
  }

  async publicKeyRaw(): Promise<CryptoKey> {
    const publicKey = await this.publicKey();
    return importRSAPublicKey(publicKey);
  }

  async publicKey(): Promise<string> {
    if (this.keyType === KeyType.JWK) {
      return this.wallet.n
    } else {
      return this.wallet.getActivePublicKey();
    }
  }

  privateKeyRaw(): Uint8Array {
    throw new Error('Method not implemented.');
  }

  async signingPublicKey(): Promise<string> {
    return this.publicKey();
  }

  async signingPublicKeyRaw(): Promise<CryptoKey> {
    return this.publicKeyRaw();
  }

  async sign(message: string) {
    let signature: string
    const data = new TextEncoder().encode(message);
    if (this.keyType === KeyType.JWK) {
      const dataToSign = new Uint8Array(data);

      // hash the message
      const hash = await crypto.subtle.digest(HASH_ALGORITHM, dataToSign);
      const cryptoKey = await importRSASigningKey(this.wallet);
      const signatureRaw = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        cryptoKey,
        hash
      );
      signature = arrayToBase64(new Uint8Array(signatureRaw));
    } else {
      const rawSignature = await (<any>window.arweaveWallet).signMessage(data);
      signature = arrayToBase64(rawSignature);
    }
    return signature;
    // const signatureOptions = {
    //   name: "RSA-PSS",
    //   saltLength: 32,
    // }
    // let rawSignature: any;
    // if (this.keyType === KeyType.JWK) {
    //   rawSignature = await this.arweave.crypto.sign(
    //     this.wallet,
    //     data
    //   );
    // } else {
    //   rawSignature = await this.wallet.signature(
    //     data, signatureOptions);
    // }
    // const signature = this.arweave.utils.bufferTob64(rawSignature);
    // return signature;
  }

  async signString(message: string): Promise<string> {
    let signature: string
    const data = new TextEncoder().encode(message);
    if (this.keyType === KeyType.JWK) {
      const dataToSign = new Uint8Array(data);

      // hash the message
      const hash = await crypto.subtle.digest(HASH_ALGORITHM, dataToSign);
      const cryptoKey = await importRSASigningKey(this.wallet);
      const signatureRaw = await crypto.subtle.sign(
        { name: "RSA-PSS", saltLength: 32 },
        cryptoKey,
        hash
      );
      signature = arrayToBase64(new Uint8Array(signatureRaw));
    } else {
      const rawSignature = await (<any>window.arweaveWallet).signMessage(data);
      signature = arrayToBase64(rawSignature);
    }
    return signature;
  }

  async getAddress() {
    const address = await this.arweave.wallets.jwkToAddress(
      this.keyType === KeyType.JWK
        ? this.wallet
        : "use-wallet"
    );
    return address;
  }

  async getPublicKeyFromAddress(address: string) {
    const publicKey = await this._getPublicKeyFromAddress(address);
    return importRSAPublicKey(publicKey);
  }

  async _getPublicKeyFromAddress(address: string) {
    try {
      const transactionId = await this.arweave.wallets.getLastTransactionID(address);
      if (transactionId) {
        const transaction = await this.arweave.transactions.get(transactionId);
        return transaction.owner
      } else {
        console.log("Could not find corresponding public key for the given address. Make sure that the member address is registered on the weave, ie. at least one transaction was made with that address.");
      }
    } catch (error) {
      console.log("Could not find corresponding public key for the given address. Make sure that the member address is registered on the weave, ie. at least one transaction was made with that address.");
      console.error("Could not find corresponding public key for the given address: " + error);
    }
  };
}

const HASH_ALGORITHM = 'SHA-256'

const ASYMMETRIC_KEY_ALGORITHM = 'RSA-OAEP'
const ASYMMETRIC_PUBLIC_EXPONENT = "AQAB"

export const signMessage = async (message: string, jwk?: any): Promise<string> => {
  let signature: string
  const data = new TextEncoder().encode(message);
  if (jwk) {
    const dataToSign = new Uint8Array(data);

    // hash the message
    const hash = await crypto.subtle.digest(HASH_ALGORITHM, dataToSign);
    const cryptoKey = await importRSASigningKey(jwk);
    const signatureRaw = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      cryptoKey,
      hash
    );
    signature = arrayToBase64(new Uint8Array(signatureRaw));
  } else {
    const rawSignature = await (<any>window.arweaveWallet).signMessage(data);
    signature = arrayToBase64(rawSignature);
  }
  return signature;
}

const importRSAPublicKey = async (publicKey: any): Promise<CryptoKey> => {
  if (publicKey) {
    return await crypto.subtle.importKey(
      "jwk",
      {
        kty: 'RSA',
        e: ASYMMETRIC_PUBLIC_EXPONENT,
        n: publicKey,
        alg: 'RSA-OAEP-256',
        ext: true
      },
      {
        name: ASYMMETRIC_KEY_ALGORITHM,
        hash: {
          name: HASH_ALGORITHM
        },
      },
      false,
      ['encrypt']
    );
  } else {
    return null
  }
}

const importRSASigningKey = async (jwk: any): Promise<CryptoKey> => {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: "RSA-PSS",
      hash: HASH_ALGORITHM
    },
    false,
    ["sign"]
  );
}

const importRSACryptoKey = async (jwk: any): Promise<CryptoKey> => {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    {
      name: ASYMMETRIC_KEY_ALGORITHM,
      hash: {
        name: HASH_ALGORITHM
      },
    },
    false,
    ["decrypt"]
  );
}

export {
  ArweaveWallet
}


// if(window.arweaveWallet) {
//   address = await window.arweaveWallet.getActiveAddress();
// publicSigningKey = await window.arweaveWallet.getActivePublicKey();
// publicKey = publicSigningKey;
// } else {
//   const Arweave = (await import("arweave")).default;
//   const arweave = Arweave.init({
//     host: "https://arweave.net",
//     port: "443",
//     protocol: "https",
//     logging: true
//   });
//   address = await arweave.wallets.jwkToAddress(options.wallet);
//   publicSigningKey = options.wallet
//   publicKey = publicSigningKey;
// }