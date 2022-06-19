import { IsNotEmpty } from 'class-validator';

export class UpdatePasswordDto {
  /**
   * The old password from the user.
   * @example "Password@123"
   */
  @IsNotEmpty()
  oldPassword: string;

  /**
   * The new password from the user.
   * @example "Password@123"
   */
  @IsNotEmpty()
  newPassword: string;
}
