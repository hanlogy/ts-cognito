import { DecodeAccessTokenResult } from '@/types';
import { decodeJwt } from 'jose';

export function decodeAccessToken(
  accessToken: string,
): DecodeAccessTokenResult | undefined {
  try {
    const { sub, exp } = decodeJwt(accessToken);

    if (typeof sub !== 'string') {
      return undefined;
    }

    return { sub, exp: typeof exp === 'number' ? exp : undefined };
  } catch {
    return undefined;
  }
}
