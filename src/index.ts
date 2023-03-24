import { AkordWallet } from "@akord/crypto";
import { AuthenticationDetails, CognitoUser, CognitoUserAttribute, CognitoUserPool, CognitoUserSession } from "amazon-cognito-identity-js";
import { FileStorage } from "./storage";


class Auth {
  public static authToken: string
  public static apiKey: string
  public static config: ApiConfig
  public static storage: Storage
  public static pool: CognitoUserPool
  private constructor() { }

  public static init(options: AuthOptions = defaultAuthOptions) {
    this.config = apiConfig(options.env)
    if (options.authToken) {
      this.authToken = options.authToken
    } else if (options.apiKey) {
      this.apiKey = options.apiKey
    } else {
      this.storage = options.storage
      this.pool = new CognitoUserPool({
        UserPoolId: this.config.userPoolId,
        ClientId: this.config.userPoolsWebClientId,
        Storage: options.storage
      })
    }
  }


  /**
  * @param  {string} email
  * @param  {string} password
  * @returns Promise with AuthSession containing Akord Wallet and jwt token
  */
  public static signIn = async function (email: string, password: string): Promise<AuthSession> {
    const { user, session } = await Auth.authenticateUser(email, password)
    const attributes = await Auth.retrieveUserAttributes(user)
    const wallet = await AkordWallet.importFromEncBackupPhrase(password, attributes["custom:encBackupPhrase"]);
    return { wallet, jwt: session.getIdToken().getJwtToken() }
  };

  /**
  * @returns Promise with AuthSession containing Akord Wallet and jwt token
  */
  public static authenticate = async function (): Promise<AuthSession> {
    const { session, user } = await Auth.getCurrentSessionUser()
    const attributes = await Auth.retrieveUserAttributes(user)
    const wallet = await AkordWallet.importFromKeystore(attributes["custom:encBackupPhrase"]);
    return { wallet, jwt: session.getIdToken().getJwtToken() }
  };

  public static signOut = async function (): Promise<void> {
    const cognitoUser = this.pool.getCurrentUser();
    if (cognitoUser != null) {
      const session = await new Promise((resolve, reject) =>
        cognitoUser.getSession((err, session: CognitoUserSession) => {
          if (err || !session) {
            reject(err || "Invalid session")
          }
          resolve(session)
        })
      )
      session
      cognitoUser.signOut();
    };
  }

  /**
  * @param  {string} email
  * @param  {string} password
  * @param  {SignUpOptions} options JSON client metadata, ex: { clientType: "CLI" }
  * @returns Promise with Akord Wallet
  */
  public static signUp = async function (email: string, password: string, options: SignUpOptions = {}): Promise<void> {
    const wallet = await AkordWallet.create(password);
    const attributes = [];
    for (const [key, value] of Object.entries({
      email,
      "custom:encBackupPhrase": wallet.encBackupPhrase,
      "custom:publicKey": wallet.publicKey(),
      "custom:publicSigningKey": wallet.signingPublicKey(),
      "custom:referrerId": options.referrerId,
      "custom:mode": "dark",
      "custom:notifications": "true"
    })) {
      attributes.push(new CognitoUserAttribute({
        Name: key,
        Value: <string>value
      }));
    }
    await new Promise((resolve, reject) =>
      this.pool.signUp(email, password, attributes, null, (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      }, { verifyUrl: options.verifyUrl })
    );
  };

  public static resendCode = async function (email: string): Promise<Object> {
    const user = Auth.getCognitoUser(email);
    return new Promise((resolve, reject) =>
      user.resendConfirmationCode((err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      })
    );
  }

  /**
  * @param  {string} email
  * @param  {string} code
  * @returns
  */
  public static verifyAccount = async function (email: string, code: string): Promise<Object> {
    const user = Auth.getCognitoUser(email);
    return new Promise((resolve, reject) =>
      user.confirmRegistration(code, false, (err, result) => {
        if (err) {
          reject(err);
        } else {
          resolve(result);
        }
      })
    );
  }

  public static changePassword = async function (currentPassword: string, newPassword: string): Promise<AuthSession> {
    const { user } = await Auth.getCurrentSessionUser()
    const attributes = await Auth.retrieveUserAttributes(user)
    const encBackupPhrase = attributes['custom:encBackupPhrase']
    const wallet = await AkordWallet.changePassword(
      currentPassword,
      newPassword,
      encBackupPhrase
    )
    await this.updateUserAttribute('custom:encBackupPhrase', wallet.encBackupPhrase)
    await new Promise((resolve, reject) =>
      user.changePassword(
        currentPassword,
        newPassword,
        (err, result) => {
          if (err) {
            reject(err)
          }
          resolve(result)
        }
      ))
    const jwt = await this.getAuthToken()
    return { wallet, jwt }
  };

  public static changePasswordSubmit = async function (email: string, code: string, password: string): Promise<void> {
    const { user } = await Auth.getCurrentSessionUser()
    await new Promise((resolve, reject) =>
      user.confirmPassword(code, password, {
        onSuccess() {
          resolve('password_changed')
        },
        onFailure(err) {
          reject(err)
        },
      })
    );
  };

  /**
   * Gets jwt token if available. For SRP auth:
   * 1. Get idToken, accessToken, refreshToken, and clockDrift from storage
   * 2. Validate the tokens if active or expired.
   * 3. If tokens are valid, return current session.
   * 4. If tokens are expired, invoke the refreshToken().
   */
  public static getAuthToken = async function (): Promise<string> {
    if (this.authToken) {
      return this.authToken
    } else if (this.apiKey) {
      return null
    } else {
      const session = (await Auth.getCurrentSessionUser()).session;
      if (!session) {
        return null
      }
      return session.getIdToken().getJwtToken();
    }
  };

  public static getAuthorization = async function (): Promise<string> {
    if (this.apiKey) {
      return this.apiKey
    } else {
      const token = await this.getAuthToken()
      if (token) {
        return `Bearer ${token}`
      }
    }
    return null
  }

  public static getUserAttributes = async function (): Promise<any> {
    const { user } = await Auth.getCurrentSessionUser()
    return await Auth.retrieveUserAttributes(user)
  }

  public static updateUserAttribute = async function (attributeName: string, attributeValue: string): Promise<any> {
    const { user } = await Auth.getCurrentSessionUser();
    const attributeList = [];
    const attribute = new CognitoUserAttribute({
      Name: attributeName,
      Value: attributeValue,
    });
    attributeList.push(attribute);

    await new Promise((resolve, reject) =>
      user.updateAttributes(attributeList, function (err, result) {
        if (err) {
          reject(err.message || JSON.stringify(err));
        }
        resolve(result);
      }))
  }

  public static enableMFA = async function (phoneNumber: string): Promise<void> {
    const { user } = await Auth.getCurrentSessionUser();
    await this.updateUserAttribute("phone", phoneNumber)
    const smsMfaSettings = {
      PreferredMfa: true,
      Enabled: true,
    };
    await new Promise((resolve, reject) =>
      user.setUserMfaPreference(smsMfaSettings, null, function (err, result) {
        if (err) {
          reject(err.message || JSON.stringify(err));
        }
        resolve("mfa_enabled");
      })
    );
  }

  public static disableMFA = async function (): Promise<void> {
    const { user } = await Auth.getCurrentSessionUser();
    const smsMfaSettings = {
      PreferredMfa: false,
      Enabled: false,
    };
    await new Promise((resolve, reject) =>
      user.setUserMfaPreference(smsMfaSettings, null, function (err, result) {
        if (err) {
          reject(err.message || JSON.stringify(err));
        }
        resolve("mfa_disabled");
      })
    );
  }

  public static generateAPIKey = async function (): Promise<string> {
    const response = await fetch(`${this.config.apiurl}/api-keys`, {
      method: 'post',
      headers: new Headers({
        'Authorization': await this.getAuthorization(),
      }),
    })
    return (await response.json()).apiKey
  }

  public static getAPIKey = async function (): Promise<string> {
    const response = await fetch(`${this.config.apiurl}/api-keys`, {
      method: 'get',
      headers: new Headers({
        'Authorization': await this.getAuthorization(),
      }),
    })
    return (await response.json()).apiKey
  }

  public static deleteAPIKey = async function (): Promise<void> {
    await fetch(`${this.config.apiurl}/api-keys`, {
      method: 'delete',
      headers: new Headers({
        'Authorization': await this.getAuthorization(),
      }),
    })
  }

  private static retrieveUserAttributes = async function (user: CognitoUser): Promise<Object> {
    return new Promise((resolve, reject) => {
      user.getUserAttributes(async function (err, result) {
        if (err) {
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

  private static getCurrentSessionUser = async function (): Promise<{
    user: CognitoUser,
    session: CognitoUserSession
  }> {

    const cognitoUser = this.pool.getCurrentUser();
    if (cognitoUser === null) {
      //return new Error("Invalid session")
    }
    return new Promise((resolve, reject) =>
      cognitoUser.getSession((err, session: CognitoUserSession) => {
        if (err || !session) {
          reject(err || "Invalid session")
        }
        resolve({ user: cognitoUser, session })
      })
    )
  }

  private static authenticateUser = async function (email: string, password: string): Promise<{
    user: CognitoUser,
    session: CognitoUserSession
  }> {
    const authenticationData = {
      Username: email,
      Password: password,
    };
    const cognitoUser = this.getCognitoUser(email);
    const authenticationDetails = new AuthenticationDetails(authenticationData);
    return new Promise((resolve, reject) =>
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
          resolve({ user: cognitoUser, session: result })
        },
        onFailure: function (err) {
          console.log(err.message);
          console.log(JSON.stringify(err));
          reject(err.message);
        }
      })
    );
  }

  private static getCognitoUser(username: string): CognitoUser {
    const userData = {
      Username: username,
      Pool: this.pool,
      Storage: this.storage
    };
    const cognitoUser = new CognitoUser(userData);
    return cognitoUser;
  }
}

type AuthOptions = {
  env?: "dev" | "v2"
  storage?: Storage
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
  return isNode() ? null : window.localStorage
}

function isNode() {
  return (typeof process !== 'undefined') && (process.release?.name === 'node')
}

export {
  Auth,
  FileStorage
}
