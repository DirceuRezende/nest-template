import { IsNotEmpty } from 'class-validator';

export class VerifyEmailTokenDto {
  /**
   * The token from verify email.
   * @example "Password@123"
   */
  @IsNotEmpty()
  token: string;
}
