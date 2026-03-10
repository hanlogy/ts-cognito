import { errors, JWTPayload } from 'jose';
import type {
  VerifyAccessFailedReason,
  VerifyAccessTokenResult,
} from '../types';

export interface JwtVerifyResult {
  payload: Pick<JWTPayload, 'sub' | 'exp'> & {
    token_use?: unknown;
    client_id?: unknown;
  };
}

export async function verifyAccessToken({
  clientId,
  verifier,
}: {
  clientId: string;
  verifier: () => Promise<JwtVerifyResult>;
}): Promise<VerifyAccessTokenResult> {
  try {
    const {
      payload: { sub, token_use, client_id, exp },
    } = await verifier();

    if (typeof sub !== 'string') {
      return { isValid: false, error: { code: 'invalidSub' } };
    }

    if (token_use !== 'access') {
      return { isValid: false, error: { code: 'invalidTokenUse' } };
    }

    if (client_id !== clientId) {
      return { isValid: false, error: { code: 'invalidClientId' } };
    }

    return {
      isValid: true,
      payload: { sub, exp: typeof exp === 'number' ? exp : undefined },
    };
  } catch (error) {
    let code: VerifyAccessFailedReason = 'unknown';
    if (error instanceof errors.JWTExpired) {
      code = 'expired';
    } else if (error instanceof errors.JWSSignatureVerificationFailed) {
      code = 'signatureVerificationFailed';
    } else if (error instanceof errors.JWTClaimValidationFailed) {
      code = 'claimValidationFailed';
    }

    return { isValid: false, error: { code } };
  }
}
