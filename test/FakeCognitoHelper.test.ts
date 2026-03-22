import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  CodeMismatchException,
  NotAuthorizedException,
  UserNotConfirmedException,
  UserNotFoundException,
  UsernameExistsException,
} from '@aws-sdk/client-cognito-identity-provider';

const jwtVerifyMock = jest.fn();
const signMock = jest.fn();

jest.mock('jose', () => {
  class SignJWT {
    setProtectedHeader() {
      return this;
    }
    setIssuer() {
      return this;
    }
    setIssuedAt() {
      return this;
    }
    setExpirationTime() {
      return this;
    }
    sign() {
      return signMock();
    }
  }

  return {
    jwtVerify: (...args: unknown[]) => {
      return jwtVerifyMock(...args);
    },
    SignJWT,
  };
});

jest.mock('../src/helpers/decodeAccessToken', () => ({
  decodeAccessToken: jest.fn(),
}));

import { FakeCognitoHelper } from '@/FakeCognitoHelper';
import { decodeAccessToken } from '../src/helpers/decodeAccessToken';
import { LocalCognitoRecord } from '@/helpers/JsonFileStorage';

const username = 'user@example.com';
const password = 'Password123!';
const newPassword = 'NewPassword123!';

describe('FakeCognitoHelper', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    signMock.mockResolvedValue('fake-access-token');
    jwtVerifyMock.mockResolvedValue({
      payload: {
        sub: 'mock-user-id',
        token_use: 'access',
        client_id: 'fake-local-client-id',
      },
    });
    (decodeAccessToken as jest.Mock).mockReturnValue(undefined); // default
  });

  test('sign up', async () => {
    const { helper, cleanup } = createTestContext();

    try {
      const result = await helper.signUp({ username, password });

      expect(result.confirmed).toBe(false);
      expect(result.id).toEqual(expect.any(String));
    } finally {
      cleanup();
    }
  });

  test('duplicate username', async () => {
    const { helper, cleanup } = createTestContext();

    try {
      await helper.signUp({ username, password });

      await expect(async () => {
        await helper.signUp({ username, password });
      }).rejects.toThrow(UsernameExistsException);
    } finally {
      cleanup();
    }
  });

  test('unconfirmed login', async () => {
    const { helper, cleanup } = createTestContext();

    try {
      await helper.signUp({ username, password });

      await expect(helper.login({ username, password })).rejects.toThrow(
        UserNotConfirmedException,
      );
    } finally {
      cleanup();
    }
  });

  test('confirm sign up and login', async () => {
    const { helper, filePath, cleanup } = createTestContext();

    try {
      await signUpAndConfirmUser(helper, filePath, username, password);

      const storedUser = readStoredUser(filePath, username);
      jwtVerifyMock.mockResolvedValue({
        payload: {
          sub: storedUser.user.id,
          token_use: 'access',
          client_id: 'fake-local-client-id',
        },
      });

      const auth = await helper.login({ username, password });

      expect(auth.accessToken).toBe('fake-access-token');
      expect(auth.refreshToken).toMatch(/^fake-refresh-token-/);
      expect(auth.expiresIn).toBe(900);
    } finally {
      cleanup();
    }
  });

  test('confirm sign up wrong code', async () => {
    const { helper, cleanup } = createTestContext();

    try {
      await helper.signUp({ username, password });

      await expect(async () => {
        await helper.confirmSignUp({
          username,
          confirmationCode: '000000',
        });
      }).rejects.toThrow(CodeMismatchException);
    } finally {
      cleanup();
    }
  });

  test('refresh token', async () => {
    const { helper, filePath, cleanup } = createTestContext();

    try {
      await signUpAndConfirmUser(helper, filePath, username, password);

      const storedUser = readStoredUser(filePath, username);
      jwtVerifyMock.mockResolvedValue({
        payload: {
          sub: storedUser.user.id,
          token_use: 'access',
          client_id: 'fake-local-client-id',
        },
      });

      const loginResult = await helper.login({ username, password });
      const refreshToken = getRequiredRefreshToken(loginResult.refreshToken);

      const refreshResult = await helper.refreshToken({ refreshToken });

      expect(refreshResult).toEqual({
        accessToken: 'fake-access-token',
        expiresIn: 900,
      });
    } finally {
      cleanup();
    }
  });

  test('refresh token not found', async () => {
    const { helper, cleanup } = createTestContext();

    try {
      await expect(
        helper.refreshToken({ refreshToken: 'missing-token' }),
      ).resolves.toBeUndefined();
    } finally {
      cleanup();
    }
  });

  test('admin get user by username', async () => {
    const { helper, filePath, cleanup } = createTestContext();

    try {
      await helper.signUp({ username, password });

      await expect(helper.adminGetUser({ username })).resolves.toEqual({
        attributes: { email: username },
      });

      expect(readStoredUser(filePath, username).user.username).toBe(username);
    } finally {
      cleanup();
    }
  });

  test('update email and verify email', async () => {
    const { helper, filePath, cleanup } = createTestContext();

    try {
      await signUpAndConfirmUser(helper, filePath, username, password);

      const auth = await helper.login({ username, password });
      const accessToken = getRequiredAccessToken(auth.accessToken);

      const storedUser = readStoredUser(filePath, username);
      jwtVerifyMock.mockResolvedValue({
        payload: {
          sub: storedUser.user.id,
          token_use: 'access',
          client_id: 'fake-local-client-id',
        },
      });

      (decodeAccessToken as jest.Mock).mockReturnValue({
        sub: storedUser.user.id,
      });

      await helper.updateUserAttributes({
        accessToken,
        attributes: [{ Name: 'email', Value: 'next@example.com' }],
      });

      const updatedUser = readStoredUser(filePath, username);
      const verifyCode = getRequiredCode(
        updatedUser.verifyUserAttributeCodes?.email,
        'Missing verify user attribute code in test storage',
      );

      expect(updatedUser.user.attributes.email).toBe('next@example.com');
      expect(updatedUser.user.attributes.email_verified).toBe('false');

      await helper.verifyUserAttribute({
        attributeName: 'email',
        code: verifyCode,
        accessToken,
      });

      const verifiedUser = readStoredUser(filePath, username);

      expect(verifiedUser.user.attributes.email_verified).toBe('true');
      expect(verifiedUser.verifyUserAttributeCodes?.email).toBeUndefined();
    } finally {
      cleanup();
    }
  });

  test('forgot password and confirm forgot password', async () => {
    const { helper, filePath, cleanup } = createTestContext();

    try {
      await signUpAndConfirmUser(helper, filePath, username, password);

      await helper.forgotPassword({ username });

      const forgotPasswordCode = getRequiredCode(
        readStoredUser(filePath, username).forgotPasswordCode,
        'Missing forgot password code in test storage',
      );

      await helper.confirmForgotPassword({
        username,
        confirmationCode: forgotPasswordCode,
        password: newPassword,
      });

      const auth = await helper.login({
        username,
        password: newPassword,
      });

      expect(auth.accessToken).toBe('fake-access-token');
    } finally {
      cleanup();
    }
  });

  test('change password wrong previous password', async () => {
    const { helper, filePath, cleanup } = createTestContext();

    try {
      await signUpAndConfirmUser(helper, filePath, username, password);

      const storedUser = readStoredUser(filePath, username);
      jwtVerifyMock.mockResolvedValue({
        payload: {
          sub: storedUser.user.id,
          token_use: 'access',
          client_id: 'fake-local-client-id',
        },
      });

      const { accessToken } = await helper.login({ username, password });
      const requiredAccessToken = getRequiredAccessToken(accessToken);

      (decodeAccessToken as jest.Mock).mockReturnValue({
        sub: storedUser.user.id,
      });

      await expect(
        helper.changePassword({
          previousPassword: 'WrongPassword123!',
          proposedPassword: newPassword,
          accessToken: requiredAccessToken,
        }),
      ).rejects.toThrow(NotAuthorizedException);
    } finally {
      cleanup();
    }
  });

  test('get user by access token not found', async () => {
    const { helper, cleanup } = createTestContext();

    try {
      jwtVerifyMock.mockRejectedValue(new Error('Invalid token'));

      await expect(
        helper.getUserByAccessToken('missing-access-token'),
      ).rejects.toThrow(UserNotFoundException);
    } finally {
      cleanup();
    }
  });
});

async function signUpAndConfirmUser(
  helper: FakeCognitoHelper,
  filePath: string,
  username: string,
  password: string,
): Promise<void> {
  await helper.signUp({ username, password });

  const signUpCode = getRequiredCode(
    readStoredUser(filePath, username).signUpCode,
    'Missing sign up code in test storage',
  );

  await helper.confirmSignUp({
    username,
    confirmationCode: signUpCode,
  });
}

function getRequiredCode(
  value: string | undefined,
  errorMessage: string,
): string {
  if (!value) {
    throw new Error(errorMessage);
  }

  return value;
}

function getRequiredAccessToken(accessToken: string | undefined): string {
  if (!accessToken) {
    throw new Error('Missing access token in test result');
  }

  return accessToken;
}

function getRequiredRefreshToken(refreshToken: string | undefined): string {
  if (!refreshToken) {
    throw new Error('Missing refresh token in test result');
  }

  return refreshToken;
}

function createTestContext(): {
  helper: FakeCognitoHelper;
  filePath: string;
  cleanup: () => void;
} {
  const dirPath = mkdtempSync(join(tmpdir(), 'fake-cognito-helper-'));
  const previousCwd = process.cwd();
  process.chdir(dirPath);
  const filePath = join(dirPath, '.cognito-local.json');
  const helper = FakeCognitoHelper.withJsonFileStorage();

  return {
    helper,
    filePath,
    cleanup: (): void => {
      process.chdir(previousCwd);
      rmSync(dirPath, { recursive: true, force: true });
    },
  };
}

function readStoredUsers(filePath: string): LocalCognitoRecord[] {
  return JSON.parse(readFileSync(filePath, 'utf8')) as LocalCognitoRecord[];
}

function readStoredUser(
  filePath: string,
  username: string,
): LocalCognitoRecord {
  const user = readStoredUsers(filePath).find((item) => {
    return item.user.username === username;
  });

  if (!user) {
    throw new Error(`User not found in test storage: ${username}`);
  }

  return user;
}
