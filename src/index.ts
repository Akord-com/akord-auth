import { AkordWallet } from "@akord/crypto";
import { Auth as JWTAuth, CognitoUser } from "@aws-amplify/auth";
import { MemoryStorage, Amplify, Hub } from '@aws-amplify/core';
import { FileStorage } from "./storage";


class Auth {
  public static authToken: string
  public static apiKey: string
  public static config: ApiConfig
  private constructor() { }

  public static init(options: AuthOptions = defaultAuthOptions) {
    this.config = apiConfig(options.env)
    if (options.authToken) {
      this.authToken = options.authToken
    } else if (options.apiKey) {
      this.apiKey = options.apiKey
    } else {
      JWTAuth.configure({
        userPoolId: this.config.userPoolId,
        userPoolWebClientId: this.config.userPoolsWebClientId,
        region: 'eu-central-1',
        storage: options.storage
      })
    }
  }

  public static configure(name: string, value: string) {
    JWTAuth.configure({
      [name]: value
    })
  }

  public static getJWTAuth() {
    return JWTAuth
  }

  /**
  * @param  {string} email
  * @param  {string} password
  * @returns Promise with AuthSession containing Akord Wallet and jwt token
  */
  public static signIn = async function (email: string, password: string): Promise<AuthSession> {
    const user = await JWTAuth.signIn(email, password)
    const jwt = await Auth.getAuthToken()
    const wallet = await AkordWallet.importFromEncBackupPhrase(password, user.attributes["custom:encBackupPhrase"]);
    return { wallet, jwt }
  };

  /**
  * @returns Promise with AuthSession containing Akord Wallet and jwt token
  */
  public static authenticate = async function (): Promise<AuthSession> {
    const jwt = await Auth.getAuthToken()
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
  * @param  {SignUpOptions} options JSON client metadata, ex: { clientType: "CLI" }
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
    const jwt = await Auth.getAuthToken()
    return { wallet, jwt };
  };

  public static resendSignUp = async function (email: string, options: SignUpOptions = {}): Promise<void> {
    await JWTAuth.resendSignUp(email, { verifyUrl: options.verifyUrl });
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

  public static changePassword = async function (currentPassword: string, newPassword: string): Promise<AuthSession> {
    const user = await JWTAuth.currentAuthenticatedUser()
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
    const jwt = await Auth.getAuthToken()
    return { wallet, jwt }
  };

  public static changePasswordSubmit = async function (email: string, code: string, password: string): Promise<void> {
    await JWTAuth.forgotPasswordSubmit(email, code, password)
  };


  /**
   * Gets jwt token if available. For SRP auth:
   * 1. Get idToken, accessToken, refreshToken, and clockDrift from storage
   * 2. Validate the tokens if active or expired.
   * 3. If tokens are valid, return current session.
   * 4. If tokens are expired, invoke the refreshToken().
   */
  public static getAuthToken = async function (): Promise<string> {
    if (Auth.authToken) {
      return Auth.authToken
    } else if (Auth.apiKey) {
      return null
    } else {
      const session = await JWTAuth.currentSession();
      if (!session) {
        return null
      }
      return session.getIdToken().getJwtToken();
    }
  };

  public static getAuthorization = async function (): Promise<string> {
    if (Auth.apiKey) {
      return Auth.apiKey
    } else {
      const token = await Auth.getAuthToken()
      if (token) {
        return `Bearer ${token}`
      }
    }
    return null
  }

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

  public static generateAPIKey = async function (): Promise<string> {
    const response = await fetch(`${Auth.config.apiurl}/api-keys`, {
      method: 'post', 
      headers: new Headers({
          'Authorization': await Auth.getAuthorization(), 
      }), 
    })
    return (await response.json()).apiKey
  }
}

type AuthOptions = {
  env?: "dev" | "v2"
  storage?: Storage | MemoryStorage
  authToken?: string
  apiKey?: string
}

const defaultAuthOptions: AuthOptions = {
  env: "v2",
  storage: getDefaultStorage(),
}

type SignUpOptions = {
  clientType?: "WEB" | "CLI"
  verifyUrl?: string
  referrerId?: string
}

type VerifySignUpOptions = {
  baseUrl?: string;
}

type AuthSession = {
  wallet: AkordWallet;
  jwt: string;
}

function apiConfig(env?: string): ApiConfig {
  switch (env) {
    case "dev":
      return {
        apiurl: "https://api.akord.link",
        userPoolId: "eu-central-1_FOAlZvgHo",
        userPoolsWebClientId: "3m7t2tk3dpldemk3geq0otrtt9"
      };
    case "v2":
    default:
      return {
        apiurl: "https://api.akord.com",
        userPoolId: "eu-central-1_glTrP1Kin",
        userPoolsWebClientId: "7u2a1pf5i6shfo7enci6bagk7u"
      };
  }
};

interface ApiConfig {
  apiurl: string,
  userPoolId: string,
  userPoolsWebClientId: string
}

function getDefaultStorage() {
  return isNode() ? MemoryStorage : window.localStorage
}

function isNode() {
  return (typeof process !== 'undefined') && (process.release?.name === 'node')
}

export {
  Auth,
  Amplify,
  Hub,
  MemoryStorage,
  FileStorage
}