import { IsEmail } from 'class-validator';

export class ForgotPasswordDto {
  /**
   * The email from the user.
   * @example "email@email.com"
   */
  @IsEmail()
  email: string;
}
