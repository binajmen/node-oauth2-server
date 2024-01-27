import OAuth2Server from "@node-oauth/oauth2-server";
import crypto from "crypto";

type Falsey = "" | 0 | false | null | undefined;

type Client = {
  id: string;
  redirectUris?: string | string[] | undefined;
  grants: string | string[];
  accessTokenLifetime?: number | undefined;
  refreshTokenLifetime?: number | undefined;
  [key: string]: any;
};

type User = {
  [key: string]: any;
};

type AuthorizationCode = {
  authorizationCode: string;
  expiresAt: Date;
  redirectUri: string;
  scope?: string[] | undefined;
  clientId: string;
  userId: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
};

type Token = {
  accessToken: string;
  accessTokenExpiresAt?: Date | undefined;
  refreshToken?: string | undefined;
  refreshTokenExpiresAt?: Date | undefined;
  scope?: string[] | undefined;
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
users.set("alice", {
  email: "alice@mail.com",
  password: "secret",
});
users.set("bob", {
  email: "bob@mail.com",
  password: "secret",
});

const codes = new Map<string, AuthorizationCode>();
const accessTokens = new Map<string, Token>();
const tokensByClientId = new Map<string, Token>();

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

    if (client.redirectUris === undefined || client.redirectUris.length === 0) {
      throw new Error("Client redirectUris is empty");
    }

    const authorizationCode = crypto.randomBytes(16).toString("hex");
    codes.set(authorizationCode, {
      authorizationCode,
      expiresAt: new Date(),
      redirectUri: client.redirectUris[0],
      scope,
      clientId: client.id,
      userId: user.id,
      codeChallenge: "string",
      codeChallengeMethod: "string",
    });

    return authorizationCode;
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

    codes.set(code.authorizationCode, {
      ...code,
      clientId: client.id,
      userId: user.id,
    });

    return { ...code, client, user };
  }

  async getAuthorizationCode(
    authorizationCode: string
  ): Promise<OAuth2Server.AuthorizationCode | Falsey> {
    console.info("getAuthorizationCode", { authorizationCode });

    const code = codes.get(authorizationCode);
    if (!code) {
      throw new Error("Authorization code not found");
    }

    const client = clients.get(code.clientId);
    if (!client) {
      throw new Error("Client not found");
    }

    const user = users.get(code.userId);
    if (!client || !user) {
      throw new Error("User not found");
    }

    return { ...code, client, user };
  }

  async revokeAuthorizationCode(
    code: OAuth2Server.AuthorizationCode
  ): Promise<boolean> {
    console.info("revokeAuthorizationCode", { code });

    codes.delete(code.authorizationCode);

    return true;
  }

  async generateAccessToken(
    client: OAuth2Server.Client,
    user: OAuth2Server.User,
    scope: string[]
  ): Promise<string> {
    console.info("getAuthorizationCode", { client, user, scope });

    const accessToken = crypto.randomBytes(16).toString("hex");
    const refreshToken = await this.generateRefreshToken(client, user, scope);

    this.saveToken(
      {
        accessToken,
        accessTokenExpiresAt: new Date(),
        refreshToken,
        refreshTokenExpiresAt: new Date(),
        scope,
        client,
        user,
      },
      client,
      user
    );

    return accessToken;
  }

  async generateRefreshToken(
    client: OAuth2Server.Client,
    user: OAuth2Server.User,
    scope: string[]
  ): Promise<string> {
    console.info("generateRefreshToken", { client, user, scope });

    return crypto.randomBytes(16).toString("hex");
  }

  async saveToken(
    token: OAuth2Server.Token,
    client: OAuth2Server.Client,
    user: OAuth2Server.User
  ): Promise<OAuth2Server.Token | Falsey> {
    console.info("saveToken", { token, client, user });

    const { client: _, user: __, ...rest } = token;

    accessTokens.set(token.accessToken, {
      ...rest,
      clientId: client.id,
      userId: user.id,
    });

    const oldToken = tokensByClientId.get(client.id);
    if (oldToken) {
      accessTokens.delete(oldToken.accessToken);
      tokensByClientId.delete(client.id);
    }

    tokensByClientId.set(client.id, {
      ...rest,
      clientId: client.id,
      userId: user.id,
    });

    return dummyToken;
  }

  async getAccessToken(
    accessToken: string
  ): Promise<OAuth2Server.Token | Falsey> {
    console.info("getAccessToken", { accessToken });

    const { clientId, userId, ...token } = await this._getAccessToken(
      accessToken
    );
    const { client, user } = await this.getClientAndUser(clientId, userId);

    return { ...token, client, user };
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

  private async _getAccessToken(accessToken: string): Promise<Token> {
    const token = accessTokens.get(accessToken);
    if (!token) {
      throw new Error("Token not found");
    }

    return token;
  }

  private async getClientAndUser(
    clientId: string,
    userId: string
  ): Promise<{ client: Client; user: User }> {
    const client = clients.get(clientId);
    if (!client) {
      throw new Error("Client not found");
    }

    const user = users.get(userId);
    if (!client || !user) {
      throw new Error("User not found");
    }

    return { client, user };
  }
}
