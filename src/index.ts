import { AkordWallet } from "@akord/crypto";
import { Auth as JWTAuth, CognitoUser } from "@aws-amplify/auth";
import { MemoryStorage } from '@aws-amplify/core';


class Auth {

  private constructor() { }

  public static init(env: "dev" | "v2", storage?: StorageType) {
    const config = apiConfig(env)
    JWTAuth.configure({
      userPoolId: config.userPoolId,
      userPoolWebClientId: config.userPoolsWebClientId,
      region: 'eu-central-1',
      storage: getStorage(storage)
    })
  }

  /**
  * @param  {string} email
  * @param  {string} password
  * @returns Promise with Akord Client instance & Akord Wallet
  */
  public static signIn = async function (email: string, password: string): Promise<AuthSession> {
    const user = await JWTAuth.signIn(email, password)
    const jwt = await Auth.getJwt()
    const wallet = await AkordWallet.importFromEncBackupPhrase(password, user.attributes["custom:encBackupPhrase"]);
    return { wallet, jwt }
  };

    /**
  * @param  {string} email
  * @param  {string} password
  * @returns Promise with Akord Client instance & Akord Wallet
  */
    public static authenticate = async function (email: string): Promise<AuthSession> {
      const jwt = await Auth.getJwt()
      const user = await JWTAuth.currentAuthenticatedUser()
      const wallet = await AkordWallet.importFromKeystore(user.attributes["custom:encBackupPhrase"]);
      return { wallet, jwt }
    };

  public static signOut = async function (): Promise<void> {
    await JWTAuth.signOut();
  };

  /**
  * @param  {string} email
  * @param  {string} password
  * @param  {any} clientMetadata JSON client metadata, ex: { clientType: "CLI" }
  * @returns Promise with Akord Wallet
  */
  public static signUp = async function (email: string, password: string, options: SignUpOptions = {}): Promise<AuthSession> {
    const wallet = await AkordWallet.create(password);
    await JWTAuth.signUp({
      username: email,
      password: password,
      clientMetadata: { verifyUrl: options.verifyUrl, clientType: options.clientType },
      attributes: {
        email,
        "custom:encBackupPhrase": wallet.encBackupPhrase,
        "custom:publicKey": wallet.publicKey(),
        "custom:publicSigningKey": wallet.signingPublicKey(),
        "custom:referrerId": options.referrerId,
        "custom:mode": "dark",
        "custom:notifications": "true"
      }
    });
    const jwt = await Auth.getJwt()
    return { wallet, jwt };
  };

  public static resendSignUp = async function (email: string, options: SignUpOptions = {}): Promise<void> {
    await Auth.resendSignUp(email, { verifyUrl: options.verifyUrl });
  }

  /**
  * @param  {string} email
  * @param  {string} code
  * @returns
  */
  public static verifyAccount = async function (email: string, code: string, options: VerifySignUpOptions): Promise<void> {
    await JWTAuth.confirmSignUp(email, code, {
      clientMetadata: { baseUrl: options.baseUrl }
    });
  };

  public static changePassword = async function (email: string, currentPassword: string, newPassword: string): Promise<AuthSession> {
    let user = await JWTAuth.currentAuthenticatedUser()
    if (!user || user.attributes['email'] !== email) {
      user = await JWTAuth.signIn(email, currentPassword)
    }
    const encBackupPhrase = user.attributes['custom:encBackupPhrase']
    const wallet = await AkordWallet.changePassword(
      currentPassword,
      newPassword,
      encBackupPhrase
    )
    await JWTAuth.updateUserAttributes(user, {
      'custom:encBackupPhrase': wallet.encBackupPhrase
    })
    await JWTAuth.changePassword(
      user,
      currentPassword,
      newPassword
    )
    const jwt = await Auth.getJwt()
    return { wallet, jwt }
  };

  /**
   * Gets jwt token
   * 1. Get idToken, accessToken, refreshToken, and clockDrift from storage
   * 2. Validate the tokens if active or expired.
   * 3. If tokens are valid, return current session.
   * 4. If tokens are expired, invoke the refreshToken().
   */
  public static getJwt = async function (): Promise<string> {
    const session = await JWTAuth.currentSession();
    if (!session) {
      return null
    }
    return session.getAccessToken().getJwtToken();
  };

  public static getUserAttributes = async function (): Promise<any> {
    const user = await JWTAuth.currentAuthenticatedUser() as CognitoUser
    return new Promise((resolve, reject) => {
      user.getUserAttributes(async function (err, result) {
        if (err) {
          console.log(err.message);
          console.log(JSON.stringify(err));
          reject(err.message);
        }
        const attributes = result.reduce(function (
          attributesObject,
          attribute
        ) {
          attributesObject[attribute.Name] = attribute.Value;
          return attributesObject;
        }, {});
        resolve(attributes);
      })
    })
  }

  public static updateUserAttribute = async function (attributeName: string, attributeValue: string): Promise<any> {
    const user = await JWTAuth.currentAuthenticatedUser();
    await JWTAuth.updateUserAttributes(user, {
      [attributeName]: attributeValue
    });
  }
}

type SignUpOptions = {
    clientType?: "WEB" | "CLI"
    verifyUrl?: string;
    referrerId?: string;
  }

type VerifySignUpOptions = {
  baseUrl?: string;
}

type AuthSession = {
  wallet: AkordWallet;
  jwt: string;
}

type StorageType = "InMemoryStorage" | "SessionStorage" | "LocalStorage"

function getStorage(storageType: StorageType) {
  switch (storageType) {
    case "InMemoryStorage":
      return MemoryStorage
    case "SessionStorage":
      return window.sessionStorage
    case "LocalStorage":
      return window.localStorage
    default:
      return isNode() ? MemoryStorage : window.localStorage
  }
}

function apiConfig(env: string): ApiConfig {
  switch (env) {
    case "v2":
    default:
      return {
        apiurl: "https://api.akord.com",
        userPoolId: "eu-central-1_glTrP1Kin",
        userPoolsWebClientId: "7u2a1pf5i6shfo7enci6bagk7u"
      };
    case "dev":
      return {
        apiurl: "https://api.akord.link",
        userPoolId: "eu-central-1_FOAlZvgHo",
        userPoolsWebClientId: "3m7t2tk3dpldemk3geq0otrtt9"
      };
  }
};

interface ApiConfig {
  apiurl: string,
  userPoolId: string,
  userPoolsWebClientId: string
}

function isNode() {
  return (typeof process !== 'undefined') && (process.release.name === 'node')
}

export {
  Auth
}