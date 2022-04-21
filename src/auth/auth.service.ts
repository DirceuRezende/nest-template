import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon from 'argon2';
import { MailService } from '../mail/mail.service';
import { UserService } from '../user/user.service';
import { PrismaService } from '../prisma/prisma.service';

import { AuthDto } from './dto';
import { CreateUserDto } from './dto/create-user.dto';
import { Auth, JwtPayload, Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
    private userService: UserService,
    private mailService: MailService,
  ) {}

  async signupLocal(dto: CreateUserDto): Promise<Auth> {
    const password = await argon.hash(dto.password);

    const user = await this.prisma.user
      .create({
        data: {
          email: dto.email,
          password: password,
          name: dto.name,
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('Credentials incorrect');
          }
        }

        throw error;
      });

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);
    this.sendEmailVerificationMail(user);
    return {
      ...tokens,
      user: {
        name: user.name,
        email: user.email,
      },
    };
  }

  async signinLocal(dto: AuthDto): Promise<Auth> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Access Denied');

    const passwordMatches = await argon.verify(user.password, dto.password);
    if (!passwordMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return {
      ...tokens,
      user: {
        name: user.name,
        email: user.email,
      },
    };
  }

  async logout(userId: number): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });
    return true;
  }

  async refreshTokens(userId: number, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });
    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');

    const rtMatches = await argon.verify(user.hashedRt, rt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: number, rt: string): Promise<void> {
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  private sendEmailVerificationMail(user: User): void {
    const token = this.jwtService.sign(
      { ...user },
      {
        secret: this.config.get<string>('JWT_SECRET'),
        expiresIn: '120m',
      },
    );

    // The url the user can click in the mail in order to verify the email address.
    const url = `${process.env.FRONTEND_URL}/auth/email/verify/${token}`;

    // Use the mailService to send the mail.
    this.mailService.sendUserConfirmation(user, 'BlaBla', url);
  }

  async verifyEmail(token: string): Promise<User> {
    // Validate token. Will throw error if it's not valid.
    let userFromTokenPayload: User;
    try {
      userFromTokenPayload = this.jwtService.verify(token, {
        secret: this.config.get<string>('AT_SECRET'),
      });
    } catch (error) {
      throw new BadRequestException('Invalid token');
    }

    // Update email verification status.
    const updatedUser = await this.userService.updateUser(
      userFromTokenPayload.id,
      {
        email_verified: true,
      },
    );

    return updatedUser;
  }
}
