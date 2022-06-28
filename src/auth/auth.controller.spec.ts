import { Test, TestingModule } from '@nestjs/testing';
import { User } from '@prisma/client';
import { decode } from 'jsonwebtoken';
import { PrismaService } from '../prisma/prisma.service';
import { AuthController } from './auth.controller';
import { Tokens } from './types';
import { MailService } from '../mail/mail.service';
import {
  BadRequestException,
  CACHE_MODULE_OPTIONS,
  ForbiddenException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { AppModule } from '../app.module';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as argon from 'argon2';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BlockListService } from '../blocklist/blocklist.service';
import { UserService } from '../user/user.service';

const user = {
  email: 'test@gmail.com',
  password: 'super-secret-password',
  name: 'test',
};

describe('Auth Flow', () => {
  let prisma: PrismaService;
  let authController: AuthController;
  let mailService: MailService;
  let moduleRef: TestingModule;
  let spySendUserConfirmation: jest.SpyInstance<Promise<void>>;
  const mockRepository = {
    set: jest.fn(),
  };
  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [
        AppModule,
        JwtModule.registerAsync({
          imports: [ConfigModule],
          useFactory: async (configService: ConfigService) => ({
            secret: configService.get<string>('JWT_SECRET'),
          }),
          inject: [ConfigService],
        }),
      ],
    })
      .overrideProvider(CACHE_MODULE_OPTIONS)
      .useValue({
        ttl: 10,
      })
      .overrideProvider(BlockListService)
      .useValue(mockRepository)
      .compile();

    prisma = moduleRef.get(PrismaService);
    authController = moduleRef.get(AuthController);
    mailService = moduleRef.get(MailService);

    spySendUserConfirmation = jest.spyOn(mailService, 'sendUserConfirmation');
    spySendUserConfirmation.mockReturnValue(Promise.resolve());
  });

  afterAll(async () => {
    await moduleRef.close();
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    await prisma.cleanDatabase();
  });

  describe('signup', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    it('should signup', async () => {
      const tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });

    it('should throw on duplicate user signup', async () => {
      let tokens: Tokens | undefined;
      try {
        await authController.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });
        tokens = await authController.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('E-mail is already in use!');
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('signin', () => {
    it('should throw if no existing user', async () => {
      let tokens: Tokens | undefined;
      try {
        tokens = await authController.signinLocal({
          email: user.email,
          password: user.password,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should login', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const tokens = await authController.signinLocal({
        email: user.email,
        password: user.password,
      });

      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });

    it('should throw if password incorrect', async () => {
      let tokens: Tokens | undefined;
      try {
        tokens = await authController.signinLocal({
          email: user.email,
          password: user.password + 'a',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('logout', () => {
    it('should pass if call to non existent user', async () => {
      mockRepository.set.mockResolvedValueOnce(null);
      const result = await authController.logout('Bearer token', 4);
      expect(mockRepository.set).toHaveBeenCalledTimes(1);
      expect(result).toBeUndefined();
    });

    it('should logout', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      let userFromDb: User | null;

      userFromDb = await prisma.user.findFirst({
        where: {
          email: user.email,
        },
      });
      expect(userFromDb?.hashedRt).toBeTruthy();

      mockRepository.set.mockResolvedValueOnce(null);
      await authController.logout('Bearer token', userFromDb?.id);
      expect(mockRepository.set).toHaveBeenCalledTimes(1);

      userFromDb = await prisma.user.findFirst({
        where: {
          email: user.email,
        },
      });

      expect(userFromDb?.hashedRt).toBeFalsy();
    });
  });

  describe('refresh', () => {
    it('should throw if no existing user', async () => {
      let tokens: Tokens | undefined;
      try {
        tokens = await authController.refreshTokens(1, '');
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if user logged out', async () => {
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      mockRepository.set.mockResolvedValueOnce(null);
      await authController.logout('Bearer token', userId);
      expect(mockRepository.set).toHaveBeenCalledTimes(1);

      let tokens: Tokens | undefined;
      try {
        tokens = await authController.refreshTokens(userId, rt);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if refresh token incorrect', async () => {
      await prisma.cleanDatabase();

      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      let tokens: Tokens | undefined;
      try {
        tokens = await authController.refreshTokens(userId, rt + 'a');
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should refresh tokens', async () => {
      await prisma.cleanDatabase();

      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;
      const at = _tokens.access_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      await new Promise((resolve) => {
        setTimeout(() => {
          resolve(true);
        }, 1000);
      });

      const tokens = await authController.refreshTokens(userId, rt);
      expect(tokens).toBeDefined();

      expect(tokens.access_token).not.toBe(at);
      expect(tokens.refresh_token).not.toBe(rt);
    });
  });

  describe('verifyEmail', () => {
    it('should verify the user', async () => {
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        return { id: userId };
      });
      const token = spySendUserConfirmation.mock.calls[0][2].split('/').at(-1);

      await authController.verifyEmail({
        token,
      });
      const prismaUser = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });
      expect(prismaUser.email_verified).toBeTruthy();
    });

    it('should throw BadRequestException when the token is invalid', async () => {
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        throw new Error();
      });

      try {
        await authController.verifyEmail({
          token: 'token',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Invalid token');
      }

      const prismaUser = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });
      expect(prismaUser.email_verified).toBeFalsy();
    });
  });

  describe('resendVerifyEmail', () => {
    it('should resend verify e-mail', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const createdUser = await prisma.user.findUnique({
        where: {
          email: user.email,
        },
      });

      await authController.resendVerifyEmail(createdUser.id);

      expect(spySendUserConfirmation).toHaveBeenCalled();
    });

    it('should throw a ForbiddenException error when user does not exist', async () => {
      try {
        await authController.resendVerifyEmail(0);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }
    });
    it('should throw an InternalServerErrorException error when an unexpected error ocurred', async () => {
      try {
        await authController.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });

        const createdUser = await prisma.user.findUnique({
          where: {
            email: user.email,
          },
        });
        const userService = moduleRef.get(UserService);
        const spy = jest.spyOn(userService, 'findById');
        spy.mockRejectedValueOnce(
          new InternalServerErrorException('Unexpected Error'),
        );
        await authController.resendVerifyEmail(createdUser.id);
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected Error');
      }
    });
  });

  describe('updatePassword', () => {
    it('should update password', async () => {
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      await authController.updatePassword(userId, {
        oldPassword: user.password,
        newPassword: 'newPassword',
      });
      const prismaUser = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });
      const newPasswordHash = await argon.verify(
        prismaUser.password,
        'newPassword',
      );
      expect(newPasswordHash).toBeTruthy();
    });

    it('should throw error', async () => {
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);
      try {
        await authController.updatePassword(userId, {
          oldPassword: 'incorrectPassword',
          newPassword: 'newPassword',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.message).toBe('Old password is not correct');
      }

      const prismaUser = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });
      const oldPasswordHash = await argon.verify(
        prismaUser.password,
        user.password,
      );
      expect(oldPasswordHash).toBeTruthy();
    });
  });

  describe('sendForgotPasswordLink', () => {
    it('should send forgot password link', async () => {
      mailService = moduleRef.get(MailService);

      const spy = jest.spyOn(mailService, 'sendResetPasswordLink');
      spy.mockReturnValueOnce(Promise.resolve());

      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      await authController.sendForgotPasswordLink({
        email: user.email,
      });

      const forgotPassword = await prisma.forgotPassword.findFirst({
        where: {
          email: user.email,
        },
      });

      expect(forgotPassword).toBeDefined();
      expect(spy).toHaveBeenCalled();
    });

    it('should return successfully even if user does not found', async () => {
      mailService = moduleRef.get(MailService);

      const spy = jest.spyOn(mailService, 'sendResetPasswordLink');

      spy.mockReturnValue(Promise.resolve());

      await authController.sendForgotPasswordLink({
        email: user.email,
      });

      const forgotPassword = await prisma.forgotPassword.findFirst({
        where: {
          email: user.email,
        },
      });

      expect(forgotPassword).toBe(null);
      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    it('should reset password', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      await authController.sendForgotPasswordLink({
        email: user.email,
      });

      const forgotPassword = await prisma.forgotPassword.findFirst({
        where: {
          email: user.email,
        },
      });

      await authController.resetPassword({
        newPassword: 'newPassword',
        token: forgotPassword.token,
      });

      const prismaUser = await prisma.user.findUnique({
        where: {
          email: user.email,
        },
      });
      const isNewPassword = await argon.verify(
        prismaUser.password,
        'newPassword',
      );
      expect(isNewPassword).toBeTruthy();
    });

    it('should throw BadRequestException when the token is invalid', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      await authController.sendForgotPasswordLink({
        email: user.email,
      });

      try {
        await authController.resetPassword({
          newPassword: 'newPassword',
          token: 'token',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        const prismaUser = await prisma.user.findUnique({
          where: {
            email: user.email,
          },
        });
        const isOldPassword = await argon.verify(
          prismaUser.password,
          user.password,
        );
        expect(isOldPassword).toBeTruthy();
      }
    });

    it('should throw BadRequestException when the token is invalid', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      await prisma.forgotPassword.create({
        data: {
          token: 'invalidToken',
          email: user.email,
        },
      });

      try {
        await authController.resetPassword({
          newPassword: 'newPassword',
          token: 'token',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        const prismaUser = await prisma.user.findUnique({
          where: {
            email: user.email,
          },
        });
        const isOldPassword = await argon.verify(
          prismaUser.password,
          user.password,
        );
        expect(isOldPassword).toBeTruthy();
      }
    });
    it('should throw BadRequestException when the token is invalid', async () => {
      await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });
      const jwtService = moduleRef.get(JwtService);
      const config = moduleRef.get(ConfigService);
      const token = await jwtService.sign(
        { email: user.email + 1, id: 1 },
        {
          secret: config.get<string>('JWT_SECRET'),
          expiresIn: config.get<string>('EMAIL_JWT_EXPIRE_IN'),
        },
      );
      await prisma.forgotPassword.create({
        data: {
          token: token,
          email: user.email,
        },
      });

      try {
        await authController.resetPassword({
          newPassword: 'newPassword',
          token,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        const prismaUser = await prisma.user.findUnique({
          where: {
            email: user.email,
          },
        });
        const isOldPassword = await argon.verify(
          prismaUser.password,
          user.password,
        );
        expect(isOldPassword).toBeTruthy();
      }
    });
    it('should throw BadRequestException when the token is invalid', async () => {
      const jwtService = moduleRef.get(JwtService);
      const config = moduleRef.get(ConfigService);
      const token = await jwtService.sign(
        { email: user.email, id: 1 },
        {
          secret: config.get<string>('JWT_SECRET'),
          expiresIn: config.get<string>('EMAIL_JWT_EXPIRE_IN'),
        },
      );
      await prisma.forgotPassword.create({
        data: {
          token: token,
          email: user.email,
        },
      });

      try {
        await authController.resetPassword({
          newPassword: 'newPassword123',
          token,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
      }
    });
  });
});
