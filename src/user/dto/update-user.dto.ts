import { IsEmail, IsString, ValidateIf } from 'class-validator';

export class UpdateUserDto {
  /**
   * The email from the user.
   * @example "email@email.com"
   */
  @IsString()
  @IsEmail()
  @ValidateIf((object, value) => value !== undefined)
  email?: string;

  /**
   * The name from the user.
   * @example "Name Surname"
   */
  @IsString()
  @ValidateIf((object, value) => value !== undefined)
  name?: string;
}
