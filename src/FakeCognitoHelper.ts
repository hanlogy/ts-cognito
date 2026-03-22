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
  type LocalCognitoRecord,
} from './helpers/JsonFileStorage';
import type { Storage } from './helpers/Storage';
import {
  JwtVerifyResult,
  verifyAccessToken,
} from './helpers/verifyAccessToken';
import { decodeAccessToken } from './helpers/decodeAccessToken';

const localJwtIssuer = 'http://localhost/fake-cognito';
const localJwtClientId = 'fake-local-client-id';

export type SignInType = 'emailAlias';

export class FakeCognitoHelper implements CognitoHelperInterface {
  static withJsonFileStorage({
    filePath,
    accessTokenExpiresIn,
    fixedCode,
    signInType,
  }: {
    filePath?: string;
    accessTokenExpiresIn?: number;
    fixedCode?: string;
    signInType?: SignInType;
  } = {}): FakeCognitoHelper {
    return new FakeCognitoHelper({
      storage: new JsonFileStorage({ filePath }),
      ...(accessTokenExpiresIn !== undefined && { accessTokenExpiresIn }),
      ...(fixedCode !== undefined && { fixedCode }),
      ...(signInType !== undefined && { signInType }),
    });
  }

  constructor({
    storage,
    accessTokenExpiresIn = 60 * 15, // 15 minutes
    fixedCode,
    signInType = 'emailAlias',
  }: {
    storage: Storage<LocalCognitoRecord>;
    accessTokenExpiresIn?: number;
    fixedCode?: string;
    signInType?: SignInType;
  }) {
    this.storage = storage;
    this.accessTokenExpiresIn = accessTokenExpiresIn;
    this.fixedCode = fixedCode;
    this.signInType = signInType;
  }

  private readonly storage: Storage<LocalCognitoRecord>;
  private accessTokenExpiresIn: number;
  private readonly fixedCode: string | undefined;
  private readonly signInType: SignInType;

  async signUp({ username, password }: SignUpParams): SignUpResult {
    const existingUser = await this.findByUsername(username);

    if (existingUser) {
      this.throwUsernameExists();
    }

    const id = randomUUID();
    const userRecord: LocalCognitoRecord = {
      user: {
        id,
        username: this.signInType === 'emailAlias' ? id : username,
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

    await this.storage.put(userRecord.user.id, userRecord);

    return {
      id: userRecord.user.id,
      confirmed: userRecord.user.confirmed,
    };
  }

  async login({ username, password }: LoginParams): LoginResult {
    const record = await this.findByUsername(username);

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
    const nextRecord: LocalCognitoRecord = {
      ...record,
      auth: {
        refreshToken: auth.refreshToken,
        expiresIn: auth.expiresIn,
      },
    };

    await this.storage.put(nextRecord.user.id, nextRecord);

    return auth;
  }

  async refreshToken({ refreshToken }: RefreshTokenParams): RefreshTokenResult {
    const record = await this.findByRefreshToken(refreshToken);

    if (!record) {
      return undefined;
    }

    const auth = await this.buildAuth(record, refreshToken);
    const nextRecord: LocalCognitoRecord = {
      ...record,
      auth: {
        refreshToken: auth.refreshToken,
        expiresIn: auth.expiresIn,
      },
    };

    await this.storage.put(nextRecord.user.id, nextRecord);

    return {
      accessToken: auth.accessToken,
      expiresIn: auth.expiresIn,
    };
  }

  async resendConfirmationCode({
    username,
  }: ResendConfirmationCodeParams): ResendConfirmationCodeResult {
    const record = await this.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.user.confirmed) {
      this.throwUserAlreadyConfirmed();
    }

    const nextRecord: LocalCognitoRecord = {
      ...record,
      signUpCode: this.buildCode(),
    };

    await this.storage.put(nextRecord.user.id, nextRecord);

    return {
      $metadata: {},
    };
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

    const nextRecord: LocalCognitoRecord = {
      ...record,
      user: {
        ...record.user,
        attributes: nextAttributes,
      },
      verifyUserAttributeCodes: nextVerifyUserAttributeCodes,
    };

    await this.storage.put(nextRecord.user.id, nextRecord);

    return {
      $metadata: {},
    };
  }

  async forgotPassword({
    username,
  }: ForgotPasswordParams): ForgotPasswordResult {
    const record = await this.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    const nextRecord: LocalCognitoRecord = {
      ...record,
      forgotPasswordCode: this.buildCode(),
    };

    await this.storage.put(nextRecord.user.id, nextRecord);
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

    const nextRecord: LocalCognitoRecord = {
      ...record,
      user: {
        ...record.user,
        attributes: nextUserAttributes,
      },
      verifyUserAttributeCodes: nextVerifyUserAttributeCodes,
    };

    await this.storage.put(nextRecord.user.id, nextRecord);

    return {
      $metadata: {},
    };
  }

  async confirmForgotPassword({
    username,
    confirmationCode,
    password,
  }: ConfirmForgotPasswordParams): ConfirmForgotPasswordResult {
    const record = await this.findByUsername(username);

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

    await this.storage.put(nextRecord.user.id, nextRecord);
  }

  async confirmSignUp({
    username,
    confirmationCode,
  }: ConfirmSignUpParams): ConfirmSignUpResult {
    const record = await this.findByUsername(username);

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

    await this.storage.put(nextRecord.user.id, nextRecord);

    return {
      $metadata: {},
    };
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

    const nextRecord: LocalCognitoRecord = {
      ...record,
      user: {
        ...record.user,
        password: proposedPassword,
      },
    };

    await this.storage.put(nextRecord.user.id, nextRecord);

    return {
      $metadata: {},
    };
  }

  async adminGetUser({ username }: AdminGetUserParams): GetUserResult {
    const record = await this.findByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    return {
      attributes: {
        email: record.user.attributes.email,
      },
    };
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

  private async findByUsername(
    username: string,
  ): Promise<LocalCognitoRecord | undefined> {
    const all = await this.storage.list();

    if (this.signInType === 'emailAlias') {
      return all.find((r) => r.user.attributes.email === username);
    }

    return all.find((r) => r.user.username === username);
  }

  private async findByRefreshToken(
    refreshToken: string,
  ): Promise<LocalCognitoRecord | undefined> {
    const all = await this.storage.list();
    return all.find((r) => r.auth?.refreshToken === refreshToken);
  }

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

  private removeSignUpCode(record: LocalCognitoRecord): LocalCognitoRecord {
    const { signUpCode: _signUpCode, ...restRecord } = record;

    return restRecord;
  }

  private removeForgotPasswordCode(
    record: LocalCognitoRecord,
  ): LocalCognitoRecord {
    const { forgotPasswordCode: _forgotPasswordCode, ...restRecord } = record;

    return restRecord;
  }

  private buildCode(): string {
    return (
      this.fixedCode ?? String(Math.floor(100000 + Math.random() * 900000))
    );
  }

  private async findUserRecordByAccessToken(
    accessToken: string,
  ): Promise<LocalCognitoRecord | undefined> {
    const userId = this.getUserIdFromAccessToken(accessToken);

    if (!userId) {
      return undefined;
    }

    return await this.storage.get(userId);
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
    record: LocalCognitoRecord,
    refreshToken?: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    const expiresIn = this.accessTokenExpiresIn;

    return {
      accessToken: await this.buildAccessToken(record, expiresIn),
      refreshToken: refreshToken ?? this.buildRefreshToken(),
      expiresIn,
    };
  }

  private async buildAccessToken(
    record: LocalCognitoRecord,
    expiresIn: number,
  ): Promise<string> {
    const nowInSeconds = Math.floor(Date.now() / 1000);

    return await new SignJWT({
      sub: record.user.id,
      username: record.user.username,
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

  private getUserIdFromAccessToken(accessToken: string): string | undefined {
    const decoded = this.decodeAccessToken(accessToken);

    return decoded?.sub;
  }
}
