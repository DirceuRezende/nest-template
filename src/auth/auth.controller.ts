import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { BlockListService } from '../blocklist/blocklist.service';

import { Public, GetCurrentUserId, GetCurrentUser } from '../common/decorators';
import { RtGuard } from '../common/guards';
import { AuthService } from './auth.service';
import {
  AuthDto,
  CreateUserDto,
  ForgotPasswordDto,
  ResetPasswordDto,
  UpdatePasswordDto,
  VerifyEmailTokenDto,
} from './dto';
import { Auth, Tokens } from './types';
@ApiBearerAuth()
@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private blockListService: BlockListService,
  ) {}

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
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @Headers('authorization') authorization: string,
    @GetCurrentUserId() userId: number,
  ): Promise<void> {
    await this.authService.logout(userId);
    await this.blockListService.set(`block:${authorization.split(' ')[1]}`, {
      userId,
    });

    return;
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

  @Get('email/verify')
  @HttpCode(HttpStatus.NO_CONTENT)
  async resendVerifyEmail(@GetCurrentUserId() userId: number): Promise<void> {
    await this.authService.resendVerifyEmail(userId);
    return;
  }

  @Patch('password/update')
  @HttpCode(HttpStatus.NO_CONTENT)
  async updatePassword(
    @GetCurrentUserId() userId: number,
    @Body() body: UpdatePasswordDto,
  ): Promise<void> {
    await this.authService.changePassword(
      userId,
      body.oldPassword,
      body.newPassword,
    );

    return;
  }

  @Public()
  @Post('password/forgotlink')
  @HttpCode(HttpStatus.NO_CONTENT)
  async sendForgotPasswordLink(@Body() body: ForgotPasswordDto): Promise<void> {
    await this.authService.sendForgotPasswordLink(body.email);
    return;
  }

  @Public()
  @Post('password/reset')
  @HttpCode(HttpStatus.NO_CONTENT)
  async resetPassword(@Body() body: ResetPasswordDto): Promise<void> {
    await this.authService.resetPassword(body.token, body.newPassword);
    return;
  }
}
