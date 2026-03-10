import {
  verifyAccessToken,
  type JwtVerifyResult,
} from '@/helpers/verifyAccessToken';
import { errors } from 'jose';

jest.mock('jose', () => {
  return {
    errors: {
      JWTExpired: class JWTExpired extends Error {},
      JWSSignatureVerificationFailed: class JWSSignatureVerificationFailed extends Error {},
      JWTClaimValidationFailed: class JWTClaimValidationFailed extends Error {},
    },
  };
});

const mockVerifier = jest.fn<Promise<JwtVerifyResult>, []>();

const mockVerifyArgs = {
  clientId: 'client-1',
  verifier: mockVerifier,
};

function mockVerifierSuccess(payload: JwtVerifyResult['payload']): void {
  mockVerifier.mockResolvedValue({
    payload,
  });
}

describe('verifyAccessToken', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('valid access token', async () => {
    mockVerifierSuccess({
      sub: 'user-1',
      token_use: 'access',
      client_id: 'client-1',
      exp: 123,
    });

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: true,
      payload: {
        sub: 'user-1',
        exp: 123,
      },
    });
  });

  test('invalid sub', async () => {
    mockVerifierSuccess({
      sub: 1 as never, // test-only invalid payload
      token_use: 'access',
      client_id: 'client-1',
      exp: 123,
    });

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'invalidSub' },
    });
  });

  test('invalid token use', async () => {
    mockVerifierSuccess({
      sub: 'user-1',
      token_use: 'id',
      client_id: 'client-1',
      exp: 123,
    });

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'invalidTokenUse' },
    });
  });

  test('invalid client id', async () => {
    mockVerifierSuccess({
      sub: 'user-1',
      token_use: 'access',
      client_id: 'client-2',
      exp: 123,
    });

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'invalidClientId' },
    });
  });

  test('expired', async () => {
    mockVerifier.mockRejectedValue(new errors.JWTExpired('foo', {}));

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'expired' },
    });
  });

  test('signature verification failed', async () => {
    mockVerifier.mockRejectedValue(new errors.JWSSignatureVerificationFailed());

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'signatureVerificationFailed' },
    });
  });

  test('claim validation failed', async () => {
    mockVerifier.mockRejectedValue(
      new errors.JWTClaimValidationFailed('foo', {}),
    );

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'claimValidationFailed' },
    });
  });

  test('unknown', async () => {
    mockVerifier.mockRejectedValue(new Error('foo'));

    await expect(verifyAccessToken(mockVerifyArgs)).resolves.toStrictEqual({
      isValid: false,
      error: { code: 'unknown' },
    });
  });
});
