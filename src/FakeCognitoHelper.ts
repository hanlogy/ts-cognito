import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  CodeMismatchException,
  NotAuthorizedException,
  UserNotConfirmedException,
  UserNotFoundException,
  UsernameExistsException,
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
  VerifyUserAttributeParams,
  VerifyUserAttributeResult,
} from './types';
import { toAttributeMap } from './helpers/toAttributeMap';

export interface LocalCognitoUserRecord {
  user: {
    id: string;
    username: string;
    password: string;
    confirmed: boolean;
    attributes: Record<string, string>;
  };
  auth?: {
    accessToken?: string;
    refreshToken?: string;
    expiresIn?: number;
  };
  signUpCode?: string;
  forgotPasswordCode?: string;
  verifyUserAttributeCodes?: Record<string, string>;
}

export class FakeCognitoHelper implements CognitoHelperInterface {
  constructor({ filePath }: { filePath?: string } = {}) {
    this.filePath =
      filePath ?? resolve(process.cwd(), '.cognito-user-local.json');

    if (!existsSync(this.filePath)) {
      writeFileSync(this.filePath, '[]', 'utf8');
    }
  }

  signUp({ username, password }: SignUpParams): SignUpResult {
    const existingUser = this.findUserRecordByUsername(username);

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

    const users = this.readUsers();
    users.push(userRecord);
    this.writeUsers(users);

    return Promise.resolve({
      id: userRecord.user.id,
      confirmed: userRecord.user.confirmed,
    });
  }

  login({ username, password }: LoginParams): LoginResult {
    const record = this.findUserRecordByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    if (record.user.password !== password) {
      this.throwIncorrectUsernameOrPassword();
    }

    if (!record.user.confirmed) {
      this.throwUserNotConfirmed();
    }

    const auth = this.buildAuth();
    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      auth: {
        accessToken: auth.accessToken,
        refreshToken: auth.refreshToken,
        expiresIn: auth.expiresIn,
      },
    };

    this.saveUserRecord(nextRecord);

    return Promise.resolve(auth);
  }

  refreshToken({ refreshToken }: RefreshTokenParams): RefreshTokenResult {
    const record = this.readUsers().find((currentRecord) => {
      return currentRecord.auth?.refreshToken === refreshToken;
    });

    if (!record) {
      return Promise.resolve(undefined);
    }

    const auth = this.buildAuth();
    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      auth: {
        accessToken: auth.accessToken,
        refreshToken,
        expiresIn: auth.expiresIn,
      },
    };

    this.saveUserRecord(nextRecord);

    return Promise.resolve({
      accessToken: nextRecord.auth?.accessToken,
      expiresIn: nextRecord.auth?.expiresIn,
    });
  }

  resendConfirmationCode({
    username,
  }: ResendConfirmationCodeParams): ResendConfirmationCodeResult {
    const record = this.findUserRecordByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      signUpCode: this.buildCode(),
    };

    this.saveUserRecord(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  verifyUserAttribute({
    attributeName,
    code,
    accessToken,
  }: VerifyUserAttributeParams): VerifyUserAttributeResult {
    const record = this.findUserRecordByAccessToken(accessToken);

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

    this.saveUserRecord(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  forgotPassword({ username }: ForgotPasswordParams): ForgotPasswordResult {
    const record = this.findUserRecordByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    const nextRecord: LocalCognitoUserRecord = {
      ...record,
      forgotPasswordCode: this.buildCode(),
    };

    this.saveUserRecord(nextRecord);

    return Promise.resolve();
  }

  updateUserAttributes({
    attributes,
    accessToken,
  }: UpdateUserAttributesParams): UpdateUserAttributesResult {
    const record = this.findUserRecordByAccessToken(accessToken);

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

    this.saveUserRecord(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  confirmForgotPassword({
    username,
    confirmationCode,
    password,
  }: ConfirmForgotPasswordParams): ConfirmForgotPasswordResult {
    const record = this.findUserRecordByUsername(username);

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

    this.saveUserRecord(nextRecord);

    return Promise.resolve();
  }

  confirmSignUp({
    username,
    confirmationCode,
  }: ConfirmSignUpParams): ConfirmSignUpResult {
    const record = this.findUserRecordByUsername(username);

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
      },
    });

    this.saveUserRecord(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  changePassword({
    previousPassword,
    proposedPassword,
    accessToken,
  }: ChangePasswordParams): ChangePasswordResult {
    const record = this.findUserRecordByAccessToken(accessToken);

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

    this.saveUserRecord(nextRecord);

    return Promise.resolve({
      $metadata: {},
    });
  }

  adminGetUser({ username }: AdminGetUserParams): GetUserResult {
    const record = this.findUserRecordByUsername(username);

    if (!record) {
      this.throwUserNotFound();
    }

    return Promise.resolve({
      attributes: {
        email: record.user.attributes.email,
      },
    });
  }

  getUserByAccessToken(accessToken: string): GetUserResult {
    const record = this.findUserRecordByAccessToken(accessToken);

    if (!record) {
      this.throwUserNotFound();
    }

    return Promise.resolve({
      attributes: {
        email: record.user.attributes.email,
      },
    });
  }

  // ----
  private readonly filePath: string;

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
  }

  private isLocalCognitoUserRecord(
    value: unknown,
  ): value is LocalCognitoUserRecord {
    if (!this.isRecord(value)) {
      return false;
    }

    if (!this.isRecord(value.user)) {
      return false;
    }

    return (
      typeof value.user.id === 'string' &&
      typeof value.user.username === 'string' &&
      typeof value.user.password === 'string' &&
      typeof value.user.confirmed === 'boolean' &&
      this.isRecord(value.user.attributes)
    );
  }

  private readUsers(): LocalCognitoUserRecord[] {
    const content = readFileSync(this.filePath, 'utf8');
    const parsed: unknown = JSON.parse(content);

    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter((item): item is LocalCognitoUserRecord => {
      return this.isLocalCognitoUserRecord(item);
    });
  }

  private writeUsers(users: LocalCognitoUserRecord[]): void {
    writeFileSync(this.filePath, JSON.stringify(users, null, 2), 'utf8');
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

  private buildAuth(): {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  } {
    return {
      accessToken: `fake-access-token-${randomUUID()}`,
      refreshToken: `fake-refresh-token-${randomUUID()}`,
      expiresIn: 3600,
    };
  }

  private findUserRecordByUsername(
    username: string,
  ): LocalCognitoUserRecord | undefined {
    return this.readUsers().find((record) => {
      return record.user.username === username;
    });
  }

  private findUserRecordByAccessToken(
    accessToken: string,
  ): LocalCognitoUserRecord | undefined {
    return this.readUsers().find((record) => {
      return record.auth?.accessToken === accessToken;
    });
  }

  private saveUserRecord(nextRecord: LocalCognitoUserRecord): void {
    const users = this.readUsers();
    const nextUsers = users.map((record) => {
      if (record.user.id === nextRecord.user.id) {
        return nextRecord;
      }

      return record;
    });

    this.writeUsers(nextUsers);
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
}
