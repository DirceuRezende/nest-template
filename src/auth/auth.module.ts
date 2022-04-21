import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AtStrategy, RtStrategy } from './strategies';

import { MailModule } from '../mail/mail.module';
import { UserModule } from '../user/user.module';

@Module({
  imports: [JwtModule.register({}), MailModule, UserModule],
  controllers: [AuthController],
  providers: [AuthService, AtStrategy, RtStrategy],
})
export class AuthModule {}
