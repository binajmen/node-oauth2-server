import OAuth2Server from "@node-oauth/oauth2-server";

type Falsey = "" | 0 | false | null | undefined;

type Client = Required<OAuth2Server.Client>;

type User = Required<OAuth2Server.User>;

type AuthorizationCode = Omit<
  Required<OAuth2Server.AuthorizationCode>,
  "client" | "user"
> & { clientId: string; userId: string };

type Token = Omit<Required<OAuth2Server.Token>, "client" | "user"> & {
  clientId: string;
  userId: string;
};

const clients = new Map<string, Client>();
clients.set("123", {
  id: "123",
  grants: ["authorization_code", "refresh_token"],
  redirectUris: ["http://localhost:3000/callback"],
  accessTokenLifetime: 3600,
  refreshTokenLifetime: 1209600,
});

const users = new Map<string, User>();
const codes = new Map<string, AuthorizationCode>();
const tokens = new Map<string, Token>();

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

  async generateAuthorizationCode(
    client: OAuth2Server.Client,
    user: OAuth2Server.User,
    scope: string[]
  ): Promise<string> {
    console.info("generateAuthorizationCode", { client, user, scope });
    return "authorization_code";
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
    console.info("saveAuthorizationCode", { code, client, user });
    return dummyAuthorizationCode;
  }

  async getAuthorizationCode(
    authorizationCode: string
  ): Promise<OAuth2Server.AuthorizationCode | Falsey> {
    console.info("getAuthorizationCode", { authorizationCode });
    return dummyAuthorizationCode;
  }

  async revokeAuthorizationCode(
    code: OAuth2Server.AuthorizationCode
  ): Promise<boolean> {
    console.info("revokeAuthorizationCode", { code });
    return true;
  }

  async generateAccessToken(
    client: OAuth2Server.Client,
    user: OAuth2Server.User,
    scope: string[]
  ): Promise<string> {
    console.info("getAuthorizationCode", { client, user, scope });
    return "access_token";
  }

  async generateRefreshToken(
    client: OAuth2Server.Client,
    user: OAuth2Server.User,
    scope: string[]
  ): Promise<string> {
    console.info("generateRefreshToken", { client, user, scope });
    return "refresh_token";
  }

  async saveToken(
    token: OAuth2Server.Token,
    client: OAuth2Server.Client,
    user: OAuth2Server.User
  ): Promise<OAuth2Server.Token | Falsey> {
    console.info("saveToken", { token, client, user });
    return dummyToken;
  }

  async getAccessToken(
    accessToken: string
  ): Promise<OAuth2Server.Token | Falsey> {
    console.info("getAccessToken", { accessToken });
    return dummyToken;
  }

  async getRefreshToken(
    refreshToken: string
  ): Promise<OAuth2Server.Token | Falsey> {
    console.info("getRefreshToken", { refreshToken });
    return dummyToken;
  }

  async revokeToken(token: OAuth2Server.Token): Promise<boolean> {
    console.info("revokeToken", { token });
    return true;
  }

  async verifyScope(
    token: OAuth2Server.Token,
    scope: string | string[]
  ): Promise<boolean> {
    console.info("verifyScope", { token, scope });
    return true;
  }

  async getClient(
    clientId: string,
    clientSecret?: string // TOFIX: why is this optional?
  ): Promise<OAuth2Server.Client | Falsey> {
    console.info("getClient", { clientId, clientSecret });
    const client = clients.get(clientId);
    return client;
  }

  async getUser(
    email: string,
    password: string
  ): Promise<OAuth2Server.User | Falsey> {
    console.info("getUser", { email, password });
    return {};
  }
}
