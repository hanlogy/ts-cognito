import { AttributeType } from '@aws-sdk/client-cognito-identity-provider';

export function toAttributeMap(
  attributes: readonly AttributeType[],
): Record<string, string> {
  return attributes.reduce<Record<string, string>>((acc, { Name, Value }) => {
    if (Name !== undefined && Value !== undefined) {
      acc[Name] = Value;
    }

    return acc;
  }, {});
}
