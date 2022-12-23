import { AkordWallet, digest } from "@akord/crypto";
import GUN from "gun";

const gun = GUN({
  peers: [
    "http://ec2-3-72-47-16.eu-central-1.compute.amazonaws.com/gun",
    "https://gun-us.herokuapp.com/gun",
    "https://gun-manhattan.herokuapp.com/gun",
  ],
  axe: false,
  localStorage: false
});

class Auth {

  constructor() { }

  /**
  * @param  {string} email
  * @param  {string} password
  * @returns Promise with Akord Client instance & Akord Wallet
  */
  public signIn = async function (email: string, password: string): Promise<{ wallet: AkordWallet }> {
    const emailHash = await digest(email);
    const publicKey = await new Promise(function (resolve, reject) {
      gun.user().auth(emailHash, password, (res) => {
        if ((<any>res).err) {
          console.error("Authentication failed.");
          console.error((<any>res).err);
          throw new Error("Authentication failed.");
        }
        console.log("Successfully authenticated: " + gun.user().is.pub);
        resolve(gun.user().is.pub);
      });
    });
    const walletData = await new Promise(function (resolve, reject) {
      gun.user(<any>publicKey).get("akord-js").get("test").get("wallets").get(emailHash).on((data, key) => {
        resolve(data);
      });
    });
    console.log(walletData);

    const wallet = await AkordWallet.importFromEncBackupPhrase(password, (<any>walletData).encBackupPhrase);
    return { wallet };
  };

  /**
  * @param  {string} email
  * @param  {string} password
  * @param  {any} clientMetadata JSON client metadata, ex: { clientType: "CLI" }
  * @returns Promise with Akord Wallet
  */
  public signUp = async function (email: string, password: string): Promise<{ wallet: AkordWallet }> {
    const wallet = await AkordWallet.create(password);
    const emailHash = await digest(email);
    const publicKey = await new Promise(function (resolve, reject) {
      gun.user().create(email, password, (res) => {
        if ((<any>res).err) {
          console.error("Authentication failed.");
          console.error((<any>res).err);
          throw new Error("Authentication failed.");
        }
        console.log("Successfully created an account: " + gun.user().is.pub);
        resolve((<any>res).pub);
      });
    });
    await new Promise(async function (resolve, reject) {
      gun.user(<any>publicKey).get("akord-js").get("test").get("wallets").get(emailHash).put({
        address: await wallet.getAddress(),
        encBackupPhrase: wallet.encBackupPhrase,
        publicKey: await wallet.publicKey(),
        publicSigningKey: await wallet.signingPublicKey(),
      }, (res) => {
        if ((<any>res).ok) {
          console.info("Successfully uploaded data to GUN.");
          resolve("");
        } else {
          console.error((<any>res).err);
          throw new Error("Failed uploading data to GUN.")
        }
      });
    });
    return { wallet };
  };

  /**
  * @param  {string} email
  * @param  {string} code
  * @returns
  */
  public verifyAccount = async function (email: string, code: string): Promise<void> {
    // TODO
  };

  // refresh JWT token
  public refresh = async function (): Promise<void> {
    // TODO
  };
};

export {
  Auth
}