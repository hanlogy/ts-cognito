import {
  AttributeType,
  ChangePasswordCommandOutput,
  ConfirmSignUpCommandOutput,
  ResendConfirmationCodeCommandOutput,
  UpdateUserAttributesCommandOutput,
  VerifyUserAttributeCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider';

export interface VerifyUserAttributeParams {
  readonly attributeName: string;
  readonly code: string;
  readonly accessToken: string;
}

export type VerifyUserAttributeResult =
  Promise<VerifyUserAttributeCommandOutput>;

export interface RefreshTokenParams {
  readonly refreshToken: string;
}

export type RefreshTokenResult = Promise<
  | {
      accessToken: string | undefined;
      expiresIn: number | undefined;
    }
  | undefined
>;

export interface ResendConfirmationCodeParams {
  readonly username: string;
}

export type ResendConfirmationCodeResult =
  Promise<ResendConfirmationCodeCommandOutput>;

export interface LoginParams {
  readonly username: string;
  readonly password: string;
}

export type LoginResult = Promise<{
  accessToken: string | undefined;
  expiresIn: number | undefined;
  refreshToken: string | undefined;
}>;

export interface SignUpParams {
  readonly username: string;
  readonly password: string;
}

export type SignUpResult = Promise<{
  id: string | undefined;
  confirmed: boolean | undefined;
}>;

export interface ForgotPasswordParams {
  readonly username: string;
}

export type ForgotPasswordResult = Promise<void>;

export interface UpdateUserAttributesParams {
  readonly attributes: readonly AttributeType[];
  readonly accessToken: string;
}

export type UpdateUserAttributesResult =
  Promise<UpdateUserAttributesCommandOutput>;

export interface ConfirmForgotPasswordParams {
  readonly username: string;
  readonly confirmationCode: string;
  readonly password: string;
}

export type ConfirmForgotPasswordResult = Promise<void>;

export interface ConfirmSignUpParams {
  readonly username: string;
  readonly confirmationCode: string;
}

export type ConfirmSignUpResult = Promise<ConfirmSignUpCommandOutput>;

export interface ChangePasswordParams {
  readonly previousPassword: string;
  readonly proposedPassword: string;
  readonly accessToken: string;
}

export type ChangePasswordResult = Promise<ChangePasswordCommandOutput>;

export interface AdminGetUserParams {
  readonly username: string;
}

export interface AdminGetUserResultData {
  attributes: {
    email: string | undefined;
  };
}

export interface GetUserResultData {
  attributes: {
    email: string | undefined;
  };
}

export type GetUserResult = Promise<GetUserResultData>;

export interface CognitoHelperInterface {
  verifyUserAttribute(
    params: VerifyUserAttributeParams,
  ): VerifyUserAttributeResult;

  refreshToken(params: RefreshTokenParams): RefreshTokenResult;

  resendConfirmationCode(
    params: ResendConfirmationCodeParams,
  ): ResendConfirmationCodeResult;

  login(params: LoginParams): LoginResult;

  signUp(params: SignUpParams): SignUpResult;

  forgotPassword(params: ForgotPasswordParams): ForgotPasswordResult;

  updateUserAttributes(
    params: UpdateUserAttributesParams,
  ): UpdateUserAttributesResult;

  confirmForgotPassword(
    params: ConfirmForgotPasswordParams,
  ): ConfirmForgotPasswordResult;

  confirmSignUp(params: ConfirmSignUpParams): ConfirmSignUpResult;

  changePassword(params: ChangePasswordParams): ChangePasswordResult;

  adminGetUser(params: AdminGetUserParams): GetUserResult;

  getUserByAccessToken(accessToken: string): GetUserResult;
}
