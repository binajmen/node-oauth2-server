import OAuth2Server from "@node-oauth/oauth2-server";

type Callback<T> = (err?: any, result?: T) => void;
type Falsey = "" | 0 | false | null | undefined;

const dummyAuthorizationCode: OAuth2Server.AuthorizationCode = {
  authorizationCode: "string",
  expiresAt: new Date(),
  redirectUri: "string",
  scope: [],
  client: {
    id: "string",
    redirectUris: [],
    grants: [],
    accessTokenLifetime: 1000,
    refreshTokenLifetime: 1000,
  },
  user: {},
  codeChallenge: "string",
  codeChallengeMethod: "string",
};

const dummyClient: OAuth2Server.Client = {
  id: "string",
  redirectUris: [],
  grants: [],
  accessTokenLifetime: 1000,
  refreshTokenLifetime: 1000,
};

const dummyToken: OAuth2Server.Token = {
  accessToken: "string",
  accessTokenExpiresAt: new Date(),
  refreshToken: "string",
  refreshTokenExpiresAt: new Date(),
  scope: [],
  client: dummyClient,
  user: {},
};

export class Model implements OAuth2Server.AuthorizationCodeModel {
  constructor() {}

  async getAuthorizationCode(
    authorizationCode: string
  ): Promise<OAuth2Server.AuthorizationCode | Falsey> {
    return dummyAuthorizationCode;
  }

  async saveAuthorizationCode(
    code: Pick<
      OAuth2Server.AuthorizationCode,
      | "authorizationCode"
      | "expiresAt"
      | "redirectUri"
      | "scope"
      | "codeChallenge"
      | "codeChallengeMethod"
    >,
    client: OAuth2Server.Client,
    user: OAuth2Server.User
  ): Promise<OAuth2Server.AuthorizationCode | Falsey> {
    return dummyAuthorizationCode;
  }

  async revokeAuthorizationCode(
    code: OAuth2Server.AuthorizationCode
  ): Promise<boolean> {
    return true;
  }

  async getClient(
    clientId: string,
    clientSecret: string
  ): Promise<OAuth2Server.Client | Falsey> {
    return dummyClient;
  }

  async getUser(
    username: string,
    password: string,
    callback?: Callback<OAuth2Server.User | Falsey>
  ): Promise<OAuth2Server.User | Falsey> {
    return {};
  }

  async saveToken(
    token: OAuth2Server.Token,
    client: OAuth2Server.Client,
    user: OAuth2Server.User
  ): Promise<OAuth2Server.Token | Falsey> {
    return dummyToken;
  }

  async getAccessToken(
    accessToken: string
  ): Promise<OAuth2Server.Token | Falsey> {
    return dummyToken;
  }

  async getRefreshToken(
    refreshToken: string
  ): Promise<OAuth2Server.Token | Falsey> {
    return dummyToken;
  }

  async revokeToken(token: OAuth2Server.Token): Promise<boolean> {
    return true;
  }

  async verifyScope(
    token: OAuth2Server.Token,
    scope: string | string[]
  ): Promise<boolean> {
    return true;
  }
}
