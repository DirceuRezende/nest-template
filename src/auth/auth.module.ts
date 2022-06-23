import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AtStrategy, RtStrategy } from './strategies';

import { MailModule } from '../mail/mail.module';
import { UserModule } from '../user/user.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BlockListModule } from '../blocklist/blocklist.module';
import { BlockListService } from '../blocklist/blocklist.service';

@Module({
  imports: [
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
      }),
      inject: [ConfigService],
    }),
    MailModule,
    UserModule,
    BlockListModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, AtStrategy, RtStrategy, BlockListService],
})
export class AuthModule {}
