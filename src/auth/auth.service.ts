import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
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

  /**
   * Update the password of a user.
   *
   * @param {User} user
   *   The user object.
   * @param oldPassword
   *   The old password of the user in plain text.
   * @param newPassword
   *   The new password in plain text.
   *
   * @returns
   */
  async changePassword(
    id: number,
    oldPassword: string,
    newPassword: string,
  ): Promise<any> {
    // Probably the password is not included in the user object. Thus, we need to reload the user and include the password.

    const user = await this.userService.findById(id);

    // Check if the old password is correct.
    const isOldPasswordCorrect: boolean = await argon.verify(
      user.password,
      oldPassword,
    );

    if (!isOldPasswordCorrect) {
      throw new UnauthorizedException('Old password not correct');
    }

    // Hash new password & update entity.
    const password = await argon.hash(newPassword);
    return await this.userService.updateUser(user.id, {
      password,
    });
  }

  /**
   * Send a reset password link to a given email that the user can then use to reset her password.
   *
   * @param {string} email
   *   The email of the user.
   *
   * @returns
   */
  async sendForgotPasswordLink(email: string) {
    const user = await this.userService.find({ email });

    // For security issues we won't throw an error if there is no user with the
    // provided email address.
    if (!user) {
      return;
    }

    // Sign a token that will expire in 5 minutes.
    const token = await this.jwtService.sign(
      { email },
      {
        secret: this.config.get<string>('JWT_SECRET'),
        expiresIn: '120m',
      },
    );

    // Create an entry in the Forgot Password table.
    await this.prisma.forgotPassword.create({
      data: {
        email,
        token,
      },
    });

    // Send email with the reset password link.
    const url = `${process.env.FRONTEND_URL}/auth/password/reset/${token}`;
    await this.mailService.sendResetPasswordLink(email, url);
  }

  /**
   * Let the user set a new password after declaring that she forgot it.
   *
   * @param {string} token
   *   The token that she got per mail. Necessary for security reasons.
   *
   * @param newPassword
   *   The new password the user wants to set.
   *
   * @returns
   */
  async resetPassword(token: string, newPassword: string): Promise<User> {
    // Load the entry from DB with the given token.
    const forgotToken = await this.prisma.forgotPassword.findFirst({
      where: {
        token,
      },
    });
    if (!forgotToken) {
      throw new BadRequestException('Invalid token');
    }

    // Decode token. Throws an error if invalid, return object with user email if valid.
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
    const user = await this.userService.find({ email: forgotToken.email });
    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = await this.userService.updateUser(user.id, {
      password: hashedPassword,
    });

    return updatedUser;
  }
}
