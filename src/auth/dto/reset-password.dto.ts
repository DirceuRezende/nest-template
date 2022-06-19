import { IsNotEmpty } from 'class-validator';

export class ResetPasswordDto {
  /**
   * The token from reset email.
   * @example "token"
   */
  @IsNotEmpty()
  token: string;

  /**
   * The new password from the user.
   * @example "Password@123"
   */
  @IsNotEmpty()
  newPassword: string;
}
