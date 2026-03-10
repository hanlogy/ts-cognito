import {
  CognitoIdentityProviderClient,
  AdminGetUserCommand,
  GetUserCommand,
  VerifyUserAttributeCommand,
  InitiateAuthCommand,
  ResendConfirmationCodeCommand,
  SignUpCommand,
  UpdateUserAttributesCommand,
  ConfirmForgotPasswordCommand,
  ConfirmSignUpCommand,
  ChangePasswordCommand,
  ForgotPasswordCommand,
} from '@aws-sdk/client-cognito-identity-provider';

import type {
  AdminGetUserParams,
  ChangePasswordParams,
  ChangePasswordResult,
  CognitoHelperInterface,
  ConfirmForgotPasswordParams,
  ConfirmForgotPasswordResult,
  ConfirmSignUpParams,
  ConfirmSignUpResult,
  DecodeAccessTokenResult,
  ForgotPasswordParams,
  ForgotPasswordResult,
  GetUserResult,
  LoginParams,
  LoginResult,
  RefreshTokenParams,
  RefreshTokenResult,
  ResendConfirmationCodeParams,
  ResendConfirmationCodeResult,
  SignUpParams,
  SignUpResult,
  UpdateUserAttributesParams,
  UpdateUserAttributesResult,
  VerifyAccessTokenResult,
  VerifyUserAttributeParams,
  VerifyUserAttributeResult,
} from './types';
import { toAttributeMap } from './helpers/toAttributeMap';
import { createRemoteJWKSet, jwtVerify, JWTVerifyGetKey } from 'jose';
import {
  JwtVerifyResult,
  verifyAccessToken,
} from './helpers/verifyAccessToken';
import { decodeAccessToken } from './helpers/decodeAccessToken';

export class CognitoHelper implements CognitoHelperInterface {
  constructor({
    client,
  }: { client?: CognitoIdentityProviderClient | undefined } = {}) {
    this.client = client ?? new CognitoIdentityProviderClient({});
    this.userPoolClientId = this.getRequiredEnv('USER_POOL_CLIENT_ID');
    this.userPoolId = this.getRequiredEnv('USER_POOL_ID');
    this.region =
      process.env.AWS_REGION ?? this.getRequiredEnv('COGNITO_REGION');
    this.issuer = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPoolId}`;
    this.jwks = createRemoteJWKSet(
      new URL(`${this.issuer}/.well-known/jwks.json`),
    );
  }

  private getRequiredEnv(
    name: 'USER_POOL_CLIENT_ID' | 'USER_POOL_ID' | 'COGNITO_REGION',
  ): string {
    const value = process.env[name];

    if (!value) {
      throw new Error(`Missing required environment variable: ${name}`);
    }

    return value;
  }

  client: CognitoIdentityProviderClient;
  userPoolClientId: string;
  userPoolId: string;
  region: string;
  issuer: string;
  jwks: JWTVerifyGetKey;

  async verifyUserAttribute({
    attributeName,
    code,
    accessToken,
  }: VerifyUserAttributeParams): VerifyUserAttributeResult {
    return await this.client.send(
      new VerifyUserAttributeCommand({
        AttributeName: attributeName,
        Code: code,
        AccessToken: accessToken,
      }),
    );
  }

  async refreshToken({ refreshToken }: RefreshTokenParams): RefreshTokenResult {
    const command = new InitiateAuthCommand({
      AuthFlow: 'REFRESH_TOKEN',
      ClientId: this.userPoolClientId,
      AuthParameters: {
        REFRESH_TOKEN: refreshToken,
      },
    });

    const { AuthenticationResult } = await this.client.send(command);
    if (!AuthenticationResult) {
      return undefined;
    }

    return {
      accessToken: AuthenticationResult.AccessToken,
      expiresIn: AuthenticationResult.ExpiresIn,
    };
  }

  async resendConfirmationCode({
    username,
  }: ResendConfirmationCodeParams): ResendConfirmationCodeResult {
    return await this.client.send(
      new ResendConfirmationCodeCommand({
        ClientId: this.userPoolClientId,
        Username: username,
      }),
    );
  }

  async login({ username, password }: LoginParams): LoginResult {
    const response = await this.client.send(
      new InitiateAuthCommand({
        AuthFlow: 'USER_PASSWORD_AUTH',
        ClientId: this.userPoolClientId,
        AuthParameters: {
          USERNAME: username,
          PASSWORD: password,
        },
      }),
    );

    const {
      AccessToken: accessToken,
      RefreshToken: refreshToken,
      ExpiresIn: expiresIn,
    } = response.AuthenticationResult ?? {};

    return {
      accessToken,
      expiresIn,
      refreshToken,
    };
  }

  async signUp({ username, password }: SignUpParams): SignUpResult {
    const { UserSub: id, UserConfirmed: confirmed } = await this.client.send(
      new SignUpCommand({
        ClientId: this.userPoolClientId,
        Username: username,
        Password: password,
      }),
    );

    return { id, confirmed };
  }

  async forgotPassword({
    username,
  }: ForgotPasswordParams): ForgotPasswordResult {
    await this.client.send(
      new ForgotPasswordCommand({
        ClientId: this.userPoolClientId,
        Username: username,
      }),
    );
  }

  async updateUserAttributes({
    attributes,
    accessToken,
  }: UpdateUserAttributesParams): UpdateUserAttributesResult {
    return await this.client.send(
      new UpdateUserAttributesCommand({
        UserAttributes: [...attributes],
        AccessToken: accessToken,
      }),
    );
  }

  async confirmForgotPassword({
    username,
    confirmationCode,
    password,
  }: ConfirmForgotPasswordParams): ConfirmForgotPasswordResult {
    await this.client.send(
      new ConfirmForgotPasswordCommand({
        ClientId: this.userPoolClientId,
        Username: username,
        ConfirmationCode: confirmationCode,
        Password: password,
      }),
    );
  }

  async confirmSignUp({
    username,
    confirmationCode,
  }: ConfirmSignUpParams): ConfirmSignUpResult {
    return await this.client.send(
      new ConfirmSignUpCommand({
        ClientId: this.userPoolClientId,
        Username: username,
        ConfirmationCode: confirmationCode,
      }),
    );
  }

  async changePassword({
    previousPassword,
    proposedPassword,
    accessToken,
  }: ChangePasswordParams): ChangePasswordResult {
    return await this.client.send(
      new ChangePasswordCommand({
        PreviousPassword: previousPassword,
        ProposedPassword: proposedPassword,
        AccessToken: accessToken,
      }),
    );
  }

  async adminGetUser({ username }: AdminGetUserParams): GetUserResult {
    const { UserAttributes: userAttributes = [] } = await this.client.send(
      new AdminGetUserCommand({
        UserPoolId: this.userPoolId,
        Username: username,
      }),
    );

    const attributes = toAttributeMap(userAttributes);

    return {
      attributes: {
        email: attributes.email,
      },
    };
  }

  async getUserByAccessToken(accessToken: string): GetUserResult {
    const { UserAttributes: userAttributes = [] } = await this.client.send(
      new GetUserCommand({
        AccessToken: accessToken,
      }),
    );

    const attributes = toAttributeMap(userAttributes);

    return {
      attributes: {
        email: attributes.email,
      },
    };
  }

  async verifyAccessToken(
    accessToken: string,
  ): Promise<VerifyAccessTokenResult> {
    return await verifyAccessToken({
      clientId: this.userPoolClientId,
      verifier: async (): Promise<JwtVerifyResult> => {
        return await jwtVerify(accessToken, this.jwks, {
          issuer: this.issuer,
          algorithms: ['RS256'],
        });
      },
    });
  }

  decodeAccessToken(accessToken: string): DecodeAccessTokenResult | undefined {
    return decodeAccessToken(accessToken);
  }
}
