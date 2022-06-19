import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class AuthDto {
  /**
   * The email address from the user.
   * @example "email@email.com"
   */
  @IsNotEmpty()
  @IsString()
  @IsEmail()
  email: string;

  /**
   * The password from the user.
   * @example "Password@123"
   */
  @IsNotEmpty()
  @IsString()
  password: string;
}
