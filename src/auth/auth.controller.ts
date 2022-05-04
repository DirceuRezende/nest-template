import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';

import { Public, GetCurrentUserId, GetCurrentUser } from '../common/decorators';
import { RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { CreateUserDto } from './dto/create-user.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import { VerifyEmailTokenDto } from './dto/verify-email-token.dto';
import { Auth, Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: CreateUserDto): Promise<Auth> {
    return this.authService.signupLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() dto: AuthDto): Promise<Auth> {
    return this.authService.signinLocal(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ): Promise<Tokens> {
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Public()
  @Get('email/verify/:token')
  @HttpCode(HttpStatus.NO_CONTENT)
  async verifyEmail(@Param() params: VerifyEmailTokenDto): Promise<void> {
    await this.authService.verifyEmail(params.token);
    return;
  }

  /**
   * Update password of a user.
   *
   * @param {Request} req
   *   The request object.
   *
   * @param {UpdatePasswordDto} body
   *   Information about the new password.
   *
   * @returns
   */
  @Patch('password/update')
  async updatePassword(
    @GetCurrentUser() user: number,
    @Body() body: UpdatePasswordDto,
  ) {
    return await this.authService.changePassword(
      user,
      body.oldPassword,
      body.newPassword,
    );
  }

  /**
   * Send email to user with a reset password link.
   *
   * @param {ForgotPasswordDto} body
   */
  @Post('password/forgotlink')
  async sendForgotPasswordLink(@Body() body: ForgotPasswordDto) {
    this.authService.sendForgotPasswordLink(body.email);
  }

  /**
   * Reset password of a user.
   *
   * @param {ResetPasswordDto} body
   *   Data about the new password.
   */
  @Post('password/reset')
  async resetPassword(@Body() body: ResetPasswordDto) {
    this.authService.resetPassword(body.token, body.newPassword);
  }
}
