import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
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
    try {
      const userEmail = await this.userService.findByEmail(dto.email);

      if (userEmail) {
        throw new BadRequestException('E-mail is already in use!');
      }

      const user = await this.userService.createUser(dto);

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
    } catch (error) {
      if (
        error instanceof BadRequestException &&
        error.message === 'E-mail is already in use!'
      ) {
        throw error;
      }
      throw new InternalServerErrorException(error);
    }
  }

  async signinLocal(dto: AuthDto): Promise<Auth> {
    let user: User;
    try {
      user = await this.userService.find(
        {
          where: {
            email: dto.email,
          },
        },
        true,
      );
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new ForbiddenException('Access Denied');
      }
      throw new InternalServerErrorException(error);
    }

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
    await this.userService.updateMany({
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
    let user: User;
    try {
      user = await this.userService.findById(userId);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new ForbiddenException('Access Denied');
      }
      throw new InternalServerErrorException(error);
    }

    if (!user.hashedRt) throw new ForbiddenException('Access Denied');

    const rtMatches = await argon.verify(user.hashedRt, rt);
    if (!rtMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: number, rt: string): Promise<void> {
    const hash = await argon.hash(rt);

    await this.userService.updateUser(userId, { hashedRt: hash });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: this.config.get<string>('AT_JWT_EXPIRE_IN'),
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: this.config.get<string>('RT_JWT_EXPIRE_IN'),
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  private sendEmailVerificationMail(user: User): void {
    const token = this.jwtService.sign(
      { id: user.id },
      {
        secret: this.config.get<string>('JWT_SECRET'),
        expiresIn: this.config.get<string>('EMAIL_JWT_EXPIRE_IN'),
      },
    );

    const url = `${process.env.FRONTEND_URL}/auth/email/verify/${token}`;

    this.mailService.sendUserConfirmation(user, 'BlaBla', url);
  }

  async resendVerifyEmail(userId: number): Promise<void> {
    let user: User;
    try {
      user = await this.userService.findById(userId);
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw new ForbiddenException('Access Denied');
      }
      throw new InternalServerErrorException(error);
    }
    this.sendEmailVerificationMail(user);
  }

  async verifyEmail(token: string): Promise<User> {
    let userFromTokenPayload: User;

    try {
      userFromTokenPayload = this.jwtService.verify(token, {
        secret: this.config.get<string>('JWT_SECRET'),
      });
    } catch (error) {
      throw new BadRequestException('Invalid token');
    }
    await this.userService.findById(userFromTokenPayload.id);

    const updatedUser = await this.userService.updateUser(
      userFromTokenPayload.id,
      {
        email_verified: true,
      },
    );

    return updatedUser;
  }

  async changePassword(
    id: number,
    oldPassword: string,
    newPassword: string,
  ): Promise<any> {
    const user = await this.userService.findById(id);

    const isOldPasswordCorrect: boolean = await argon.verify(
      user.password,
      oldPassword,
    );

    if (!isOldPasswordCorrect) {
      throw new UnauthorizedException('Old password is not correct');
    }

    const password = await argon.hash(newPassword);

    return await this.userService.updateUser(user.id, {
      password,
    });
  }

  async sendForgotPasswordLink(email: string) {
    try {
      await this.userService.find({ where: { email } });
    } catch (error) {
      if (error instanceof BadRequestException) {
        return;
      }
    }
    try {
      const token = await this.jwtService.sign(
        { email },
        {
          secret: this.config.get<string>('JWT_SECRET'),
          expiresIn: this.config.get<string>('EMAIL_JWT_EXPIRE_IN'),
        },
      );

      await this.prisma.forgotPassword.upsert({
        where: {
          email,
        },
        create: {
          email,
          token,
        },
        update: {
          email,
          token,
        },
      });

      // Send email with the reset password link.
      const url = `${process.env.FRONTEND_URL}/auth/password/reset/${token}`;

      await this.mailService.sendResetPasswordLink(email, url);
    } catch (error) {
      throw new InternalServerErrorException(error);
    }
  }

  async resetPassword(token: string, newPassword: string): Promise<User> {
    const forgotToken = await this.prisma.forgotPassword.findFirst({
      where: {
        token,
      },
    });
    if (!forgotToken) {
      throw new BadRequestException('Invalid token');
    }

    let emailFromToken: any;
    try {
      emailFromToken = this.jwtService.verify(token, {
        secret: this.config.get<string>('JWT_SECRET'),
      });
    } catch (error) {
      throw new BadRequestException('Invalid token');
    }

    if (emailFromToken.email !== forgotToken.email) {
      throw new BadRequestException('Invalid token');
    }

    const hashedPassword = await argon.hash(newPassword);

    const user = await this.userService.find({
      where: { email: forgotToken.email },
    });

    const updatedUser = await this.userService.updateUser(user.id, {
      password: hashedPassword,
    });

    return updatedUser;
  }
}
