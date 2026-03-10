import { createSecretKey, randomUUID } from 'node:crypto';
import {
  CodeMismatchException,
  InvalidParameterException,
  NotAuthorizedException,
  UserNotConfirmedException,
  UserNotFoundException,
  UsernameExistsException,
} from '@aws-sdk/client-cognito-identity-provider';
import { jwtVerify, SignJWT } from 'jose';
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
import {
  JsonFileStorage,
  type LocalCognitoUserRecord,
} from './helpers/JsonFileStorage';
import {
  JwtVerifyResult,
  verifyAccessToken,
} from './helpers/verifyAccessToken';
import { decodeAccessToken } from './helpers/decodeAccessToken';

const localJwtIssuer = 'http://localhost/fake-cognito';
const localJwtClientId = 'fake-local-client-id';
const localJwtExpiresInSeconds = 60 * 15; // 15 minutes

export class FakeCognitoHelper implements CognitoHelperInterface {
  constructor({ filePath }: { filePath?: string } = {}) {
    this.storage = new JsonFileStorage({ filePath });
  }

  private readonly storage: JsonFileStorage;

  signUp({ username, password }: SignUpParams): SignUpResult {
    const existingUser = this.storage.findByUsername(username);

    if (existingUser) {
      this.throwUsernameExists();
    }

    const userRecord: LocalCognitoUserRecord = {
      user: {
        id: randomUUID(),
        username,
        password,
        confirmed: false,
        attributes: {
          email: username,
          email_verified: 'false',
        },
      },
      signUpCode: this.buildCode(),
      verifyUserAttributeCodes: {},
    };

    // Save through shared storage.
    this.storage.add(userRecord);

    return Promise.resolve({
      id: userRecord.user.id,
      confirmed: userRecord.user.confirmed,
    });
  }

  async login({ username, password }: LoginParams): LoginResult {
    const record = this.storage.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.user.password !== password) {
      this.throwIncorrectUsernameOrPassword();
    }

    if (!record.user.confirmed) {
      this.throwUserNotConfirmed();
    }

    const auth = await this.buildAuth(record);
    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      auth: {
        refreshToken: auth.refreshToken,
        expiresIn: auth.expiresIn,
      },
    };

    this.storage.update(nextRecord);

    return auth;
  }

  async refreshToken({ refreshToken }: RefreshTokenParams): RefreshTokenResult {
    // Read refresh token from shared storage cache.
    const record = this.storage.findByRefreshToken(refreshToken);

    if (!record) {
      return undefined;
    }

    const auth = await this.buildAuth(record, refreshToken);
    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      auth: {
        refreshToken: auth.refreshToken,
        expiresIn: auth.expiresIn,
      },
    };

    this.storage.update(nextRecord);

    return {
      accessToken: auth.accessToken,
      expiresIn: auth.expiresIn,
    };
  }

  resendConfirmationCode({
    username,
  }: ResendConfirmationCodeParams): ResendConfirmationCodeResult {
    const record = this.storage.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.user.confirmed) {
      this.throwUserAlreadyConfirmed();
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      signUpCode: this.buildCode(),
    };

    this.storage.update(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  async verifyUserAttribute({
    attributeName,
    code,
    accessToken,
  }: VerifyUserAttributeParams): VerifyUserAttributeResult {
    const record = await this.findUserRecordByAccessToken(accessToken);

    if (!record) {
      this.throwUserNotFound();
    }

    const verifyUserAttributeCodes = record.verifyUserAttributeCodes ?? {};
    const savedCode = verifyUserAttributeCodes[attributeName];

    if (savedCode !== code) {
      this.throwCodeMismatch();
    }

    const nextVerifyUserAttributeCodes = this.removeVerifyUserAttributeCode(
      verifyUserAttributeCodes,
      attributeName,
    );

    const nextAttributes = {
      ...record.user.attributes,
    };

    if (attributeName === 'email') {
      nextAttributes.email_verified = 'true';
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      user: {
        ...record.user,
        attributes: nextAttributes,
      },
      verifyUserAttributeCodes: nextVerifyUserAttributeCodes,
    };

    this.storage.update(nextRecord);

    return {
      $metadata: {},
    };
  }

  forgotPassword({ username }: ForgotPasswordParams): ForgotPasswordResult {
    const record = this.storage.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      forgotPasswordCode: this.buildCode(),
    };

    this.storage.update(nextRecord);

    return Promise.resolve();
  }

  async updateUserAttributes({
    attributes,
    accessToken,
  }: UpdateUserAttributesParams): UpdateUserAttributesResult {
    const record = await this.findUserRecordByAccessToken(accessToken);

    if (!record) {
      this.throwUserNotFound();
    }

    const nextAttributes = toAttributeMap(attributes);
    const nextVerifyUserAttributeCodes = {
      ...(record.verifyUserAttributeCodes ?? {}),
    };
    const nextUserAttributes = {
      ...record.user.attributes,
      ...nextAttributes,
    };

    if (nextAttributes.email !== undefined) {
      nextUserAttributes.email_verified = 'false';
      nextVerifyUserAttributeCodes.email = this.buildCode();
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      user: {
        ...record.user,
        attributes: nextUserAttributes,
      },
      verifyUserAttributeCodes: nextVerifyUserAttributeCodes,
    };

    this.storage.update(nextRecord);

    return {
      $metadata: {},
    };
  }

  confirmForgotPassword({
    username,
    confirmationCode,
    password,
  }: ConfirmForgotPasswordParams): ConfirmForgotPasswordResult {
    const record = this.storage.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.forgotPasswordCode !== confirmationCode) {
      this.throwCodeMismatch();
    }

    const nextRecord = this.removeForgotPasswordCode({
      ...record,
      user: {
        ...record.user,
        password,
      },
    });

    this.storage.update(nextRecord);

    return Promise.resolve();
  }

  confirmSignUp({
    username,
    confirmationCode,
  }: ConfirmSignUpParams): ConfirmSignUpResult {
    const record = this.storage.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.signUpCode !== confirmationCode) {
      this.throwCodeMismatch();
    }

    const nextRecord = this.removeSignUpCode({
      ...record,
      user: {
        ...record.user,
        confirmed: true,
        attributes: {
          ...record.user.attributes,
          email_verified: 'true',
        },
      },
    });

    this.storage.update(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  async changePassword({
    previousPassword,
    proposedPassword,
    accessToken,
  }: ChangePasswordParams): ChangePasswordResult {
    const record = await this.findUserRecordByAccessToken(accessToken);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.user.password !== previousPassword) {
      this.throwNotAuthorized();
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      user: {
        ...record.user,
        password: proposedPassword,
      },
    };

    this.storage.update(nextRecord);

    return {
      $metadata: {},
    };
  }

  adminGetUser({ username }: AdminGetUserParams): GetUserResult {
    const record = this.storage.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    return Promise.resolve({
      attributes: {
        email: record.user.attributes.email,
      },
    });
  }

  async getUserByAccessToken(accessToken: string): GetUserResult {
    const record = await this.findUserRecordByAccessToken(accessToken);

    if (!record) {
      this.throwUserNotFound();
    }

    return {
      attributes: {
        email: record.user.attributes.email,
      },
    };
  }

  async verifyAccessToken(
    accessToken: string,
  ): Promise<VerifyAccessTokenResult> {
    return await verifyAccessToken({
      clientId: localJwtClientId,
      verifier: async (): Promise<JwtVerifyResult> => {
        return await jwtVerify(accessToken, this.localJwtSecret, {
          issuer: localJwtIssuer,
        });
      },
    });
  }

  decodeAccessToken(accessToken: string): DecodeAccessTokenResult | undefined {
    return decodeAccessToken(accessToken);
  }

  // ----
  private readonly localJwtSecret = createSecretKey(
    Buffer.from('local-fake-secret-'.padEnd(32, 'x'), 'utf8'),
  );

  private removeVerifyUserAttributeCode(
    verifyUserAttributeCodes: Record<string, string>,
    attributeName: string,
  ): Record<string, string> {
    return Object.fromEntries(
      Object.entries(verifyUserAttributeCodes).filter(([key]) => {
        return key !== attributeName;
      }),
    );
  }

  private removeSignUpCode(
    record: LocalCognitoUserRecord,
  ): LocalCognitoUserRecord {
    const { signUpCode: _signUpCode, ...restRecord } = record;

    return restRecord;
  }

  private removeForgotPasswordCode(
    record: LocalCognitoUserRecord,
  ): LocalCognitoUserRecord {
    const { forgotPasswordCode: _forgotPasswordCode, ...restRecord } = record;

    return restRecord;
  }

  private buildCode(): string {
    return String(Math.floor(100000 + Math.random() * 900000));
  }

  private async findUserRecordByAccessToken(
    accessToken: string,
  ): Promise<LocalCognitoUserRecord | undefined> {
    const userId = await this.getUserIdFromAccessToken(accessToken);

    if (!userId) {
      return undefined;
    }

    return this.storage.findById(userId);
  }

  private buildExceptionData(message: string): {
    $metadata: Record<string, unknown>;
    message: string;
  } {
    return { $metadata: {}, message };
  }

  private throwUsernameExists(): never {
    throw new UsernameExistsException(
      this.buildExceptionData('User already exists'),
    );
  }

  private throwUserNotFound(): never {
    throw new UserNotFoundException(
      this.buildExceptionData('User does not exist.'),
    );
  }

  private throwIncorrectUsernameOrPassword(): never {
    throw new NotAuthorizedException(
      this.buildExceptionData('Incorrect username or password.'),
    );
  }

  private throwUserNotConfirmed(): never {
    throw new UserNotConfirmedException(
      this.buildExceptionData('User is not confirmed.'),
    );
  }

  private throwCodeMismatch(): never {
    throw new CodeMismatchException(
      this.buildExceptionData(
        'Invalid verification code provided, please try again.',
      ),
    );
  }

  private throwNotAuthorized(): never {
    throw new NotAuthorizedException(
      this.buildExceptionData('Incorrect username or password.'),
    );
  }

  private throwUserAlreadyConfirmed(): never {
    throw new InvalidParameterException(
      this.buildExceptionData('User is already confirmed.'),
    );
  }

  private async buildAuth(
    record: LocalCognitoUserRecord,
    refreshToken?: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    const expiresIn = localJwtExpiresInSeconds;

    return {
      accessToken: await this.buildAccessToken(record, expiresIn),
      refreshToken: refreshToken ?? this.buildRefreshToken(),
      expiresIn,
    };
  }

  private async buildAccessToken(
    record: LocalCognitoUserRecord,
    expiresIn: number,
  ): Promise<string> {
    const nowInSeconds = Math.floor(Date.now() / 1000);

    return await new SignJWT({
      sub: record.user.id,
      username: record.user.id,
      token_use: 'access',
      client_id: localJwtClientId,
      auth_time: nowInSeconds,
      scope: 'aws.cognito.signin.user.admin',
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setIssuer(localJwtIssuer)
      .setIssuedAt(nowInSeconds)
      .setExpirationTime(nowInSeconds + expiresIn)
      .sign(this.localJwtSecret);
  }

  private buildRefreshToken(): string {
    return `fake-refresh-token-${randomUUID()}`;
  }

  // Extract user id from verified access token.
  private async getUserIdFromAccessToken(
    accessToken: string,
  ): Promise<string | undefined> {
    const decoded = this.decodeAccessToken(accessToken);

    return await Promise.resolve(decoded?.sub);
  }
}
