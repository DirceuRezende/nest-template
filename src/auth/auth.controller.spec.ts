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
  UnauthorizedException,
} from '@nestjs/common';
import { AppModule } from '../app.module';
import { JwtModule, JwtService } from '@nestjs/jwt';
import * as argon from 'argon2';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BlockListService } from '../blocklist/blocklist.service';
import { BlockListModule } from 'src/blocklist/blocklist.module';

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
      .overrideProvider(CACHE_MODULE_OPTIONS) // exported from @nestjs/common
      .useValue({
        ttl: 10,
      })
      .overrideProvider(BlockListService)
      .useValue(mockRepository)
      .compile();

    prisma = moduleRef.get(PrismaService);
    authController = moduleRef.get(AuthController);
    mailService = moduleRef.get(MailService);

    const spy = jest.spyOn(mailService, 'sendUserConfirmation');
    spy.mockReturnValue(Promise.resolve());
  });

  afterAll(async () => {
    await moduleRef.close();
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
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Credentials incorrect');
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('signin', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });
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
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

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

      // logout
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
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

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
      // signup and save refresh token
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      // get user id from refresh token
      // also possible to get using prisma like above
      // but since we have the rt already, why not just decoding it
      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      // logout the user so the hashedRt is set to null
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
      // log in the user again and save rt + at
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;
      const at = _tokens.access_token;

      const decoded = decode(rt);
      const userId = Number(decoded?.sub);

      // since jwt uses seconds signature we need to wait for 1 second to have new jwts
      await new Promise((resolve) => {
        setTimeout(() => {
          resolve(true);
        }, 1000);
      });

      const tokens = await authController.refreshTokens(userId, rt);
      expect(tokens).toBeDefined();

      // refreshed tokens should be different
      expect(tokens.access_token).not.toBe(at);
      expect(tokens.refresh_token).not.toBe(rt);
    });
  });

  describe('verifyEmail', () => {
    beforeEach(async () => {
      await prisma.cleanDatabase();
    });

    it('should verify the user', async () => {
      const mailService = moduleRef.get(MailService);
      const spyMail = jest.spyOn(mailService, 'sendUserConfirmation');
      spyMail.mockClear();
      spyMail.mockReturnValue(Promise.resolve());

      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;
      // get user id from refresh token
      // also possible to get using prisma like above
      // but since we have the rt already, why not just decoding it
      const decoded = decode(rt);
      const userId = Number(decoded?.sub);
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        return { id: userId };
      });
      const token = spyMail.mock.calls[0][2].split('/').at(-1);

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

      // get user id from refresh token
      // also possible to get using prisma like above
      // but since we have the rt already, why not just decoding it
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

  describe('updatePassword', () => {
    beforeEach(async () => {
      await prisma.cleanDatabase();
    });

    it('should update password', async () => {
      // signup and save refresh token
      const _tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const rt = _tokens.refresh_token;

      // get user id from refresh token
      // also possible to get using prisma like above
      // but since we have the rt already, why not just decoding it
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

      // get user id from refresh token
      // also possible to get using prisma like above
      // but since we have the rt already, why not just decoding it
      const decoded = decode(rt);
      const userId = Number(decoded?.sub);
      try {
        await authController.updatePassword(userId, {
          oldPassword: 'incorrectPassword',
          newPassword: 'newPassword',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.message).toBe('Old password not correct');
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
    beforeEach(async () => {
      await prisma.cleanDatabase();
      jest.clearAllMocks();
    });

    it('should send forgot password link', async () => {
      mailService = moduleRef.get(MailService);

      const spy = jest.spyOn(mailService, 'sendResetPasswordLink');
      spy.mockReturnValueOnce(Promise.resolve());

      // signup and save refresh token
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

    it('should return successfully even if user not found', async () => {
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
    beforeEach(async () => {
      await prisma.cleanDatabase();
    });

    it('should reset password', async () => {
      // signup and save refresh token
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
          expiresIn: '120m',
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
          expiresIn: '120m',
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
        expect(error.message).toBe('User not found');
      }
    });
  });
});
