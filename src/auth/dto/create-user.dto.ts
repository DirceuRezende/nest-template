import { IsNotEmpty, IsString } from 'class-validator';

export class CreateUserDto {
  /**
   * The name address from the user.
   * @example "Name Surname"
   */
  @IsNotEmpty()
  @IsString()
  name: string;

  /**
   * The email from the user.
   * @example "email@email.com"
   */
  @IsNotEmpty()
  @IsString()
  email: string;

  /**
   * The password from the user.
   * @example "Password@123"
   */
  @IsNotEmpty()
  @IsString()
  password: string;
}
