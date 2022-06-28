import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import * as argon from 'argon2';
import { UserService } from '../user/user.service';
import { MailService } from '../mail/mail.service';
import {
  BadRequestException,
  ForbiddenException,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { User } from '@prisma/client';

const user = {
  email: 'test@gmail.com',
  password: 'super-secret-password',
  name: 'test',
};

describe('AuthService', () => {
  let authService: AuthService;
  let moduleRef: TestingModule;

  const mockPrismaService = {
    user: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
      upsert: jest.fn(),
    },
    forgotPassword: {
      upsert: jest.fn(),
      findFirst: jest.fn(),
    },
  };

  const mockMailService = {
    sendUserConfirmation: jest.fn(),
    sendResetPasswordLink: jest.fn(),
  };

  const mockUserService = {
    updateUser: jest.fn(),
    find: jest.fn(),
    findById: jest.fn(),
    findByEmail: jest.fn(),
    createUser: jest.fn(),
    updateMany: jest.fn(),
  };

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [JwtModule.register({})],
      providers: [
        AuthService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
        ConfigService,
        {
          provide: UserService,
          useValue: mockUserService,
        },
        {
          provide: MailService,
          useValue: mockMailService,
        },
      ],
    }).compile();

    authService = moduleRef.get(AuthService);
  });

  beforeEach(() => {
    jest.resetAllMocks();
    jest.clearAllMocks();
  });

  describe('signup', () => {
    it('should signup', async () => {
      mockUserService.createUser.mockResolvedValueOnce({
        ...user,
        id: '1',
      });
      const tokens = await authService.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });
      expect(mockMailService.sendUserConfirmation).toHaveBeenCalled();
      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });

    it('should throw an error on duplicate user signup', async () => {
      let tokens: Tokens | undefined;
      mockUserService.findByEmail.mockRejectedValueOnce(
        new BadRequestException('E-mail is already in use!'),
      );
      try {
        tokens = await authService.signupLocal({
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

    it('should throw an error on unexpected error', async () => {
      let tokens: Tokens | undefined;
      mockUserService.findByEmail.mockRejectedValueOnce(
        new ForbiddenException('Unexpected error!'),
      );
      try {
        tokens = await authService.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected error!');
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('signin', () => {
    it('should throw if no existing user', async () => {
      mockUserService.find.mockRejectedValueOnce(
        new BadRequestException('User does not found'),
      );
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.signinLocal({
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
      const password = await argon.hash(user.password);
      mockUserService.find.mockResolvedValueOnce({
        ...user,
        password,
        id: '1',
      });

      const tokens = await authService.signinLocal({
        email: user.email,
        password: user.password,
      });

      expect(tokens.access_token).toBeTruthy();
      expect(tokens.refresh_token).toBeTruthy();
    });

    it('should throw if password incorrect', async () => {
      const password = await argon.hash(user.password);
      mockUserService.find.mockResolvedValueOnce({
        ...user,
        password,
        id: '1',
      });
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.signinLocal({
          email: user.email,
          password: user.password + 'a',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if unexpected error happens', async () => {
      mockUserService.find.mockRejectedValueOnce(new Error('Unexpected error'));
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.signinLocal({
          email: user.email,
          password: user.password,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe('Unexpected error');
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('logout', () => {
    it('should pass if call to non existent user', async () => {
      const result = await authService.logout(4);
      expect(result).toBeDefined();
      expect(mockUserService.updateMany).toHaveBeenCalled();
    });
  });

  describe('refresh', () => {
    it('should throw if not existing user', async () => {
      mockUserService.findById.mockRejectedValueOnce(
        new BadRequestException('User does not found'),
      );
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, '');
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });
    it('should throw InternalServerErrorException if an unexpected error has occurred', async () => {
      mockUserService.findById.mockRejectedValueOnce(
        new Error('Unexpected error'),
      );
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, '');
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected error');
      }

      expect(tokens).toBeUndefined();
    });
    it('should throw if user logged out', async () => {
      mockUserService.findById.mockResolvedValueOnce({
        hashedRt: undefined,
      });
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, '');
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if refresh token incorrect', async () => {
      const rt = 'hash';
      const hashedRt = await argon.hash(rt);
      mockUserService.findById.mockResolvedValueOnce({
        hashedRt,
      });
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, '');
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if refresh token incorrect', async () => {
      const rt = 'hash';
      const hashedRt = await argon.hash(rt);
      mockUserService.findById.mockResolvedValueOnce({
        hashedRt,
      });

      const tokens = await authService.refreshTokens(1, rt);

      expect(tokens).toBeDefined();

      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
    });
  });

  describe('updateRtHash', () => {
    it('should call userService.updateUser', async () => {
      await authService.updateRtHash(1, 'hash');

      expect(mockUserService.updateUser).toHaveBeenCalled();
    });
  });

  describe('verifyEmail', () => {
    it('should return a User with email_verified equal true if token is valid', async () => {
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockReturnValue({ user, id: 1 });
      mockUserService.updateUser.mockResolvedValueOnce({
        ...user,

        email_verified: true,
      });

      const r = await authService.verifyEmail('token');

      expect(spy).toHaveBeenCalled();
      expect(spy).toHaveBeenCalledWith('token', { secret: 'secret' });
      expect(mockUserService.updateUser).toHaveBeenCalled();
      expect(mockUserService.updateUser).toHaveBeenCalledWith(1, {
        email_verified: true,
      });
      expect(r).toMatchObject({
        ...user,
        email_verified: true,
      });
    });

    it('should throw a BadRequestException when token is invalid', async () => {
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        throw new BadRequestException('Invalid token');
      });

      try {
        await authService.verifyEmail('token');
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Invalid token');
      }

      expect(spy).toHaveBeenCalled();
      expect(spy).toHaveBeenCalledWith('token', { secret: 'secret' });
    });
  });

  describe('changePassword', () => {
    it('should change password when the user is correct', async () => {
      const hashedPassword = await argon.hash('password');
      const userWithHashedPassword: Partial<User> = {
        ...user,
        password: hashedPassword,
        id: 1,
      };

      mockUserService.findById.mockResolvedValueOnce(userWithHashedPassword);
      mockUserService.updateUser.mockResolvedValueOnce(userWithHashedPassword);

      const updatedUser = await authService.changePassword(
        1,
        'password',
        'newPassword',
      );
      expect(updatedUser).toMatchObject(userWithHashedPassword);
      expect(mockUserService.updateUser).toHaveBeenCalled();
    });

    it('should throw BadRequestException when oldPassword is invalid', async () => {
      const hashedPassword = await argon.hash('password');
      const userWithHashedPassword: Partial<User> = {
        ...user,
        password: hashedPassword,
        id: 1,
      };

      try {
        mockUserService.updateUser.mockResolvedValueOnce(
          userWithHashedPassword,
        );
        mockUserService.findById.mockResolvedValueOnce(userWithHashedPassword);
        await authService.changePassword(1, 'test', 'newPassword');
        expect(user).toMatchObject(userWithHashedPassword);
        expect(mockUserService.updateUser).toHaveBeenCalled();
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.message).toBe('Old password is not correct');
      }
    });
  });
  describe('sendForgotPasswordLink', () => {
    it('should do nothing when e-mail is invalid', async () => {
      mockUserService.find.mockRejectedValueOnce(
        new BadRequestException('User does not found'),
      );
      const sendForgotPasswordLinkReturn =
        await authService.sendForgotPasswordLink('example@example.com');
      expect(sendForgotPasswordLinkReturn).toBeUndefined();
      expect(mockMailService.sendResetPasswordLink).not.toHaveBeenCalled();
    });

    it('should do nothing when e-mail is invalid', async () => {
      mockUserService.find.mockResolvedValueOnce(user);
      mockPrismaService.forgotPassword.upsert.mockRejectedValueOnce(
        new Error('Unexpected Error'),
      );
      try {
        await authService.sendForgotPasswordLink('example@example.com');
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected Error');
      }
    });

    it('should call sendResetPasswordLink correctly', async () => {
      const jwtService = moduleRef.get(JwtService);
      const config = moduleRef.get(ConfigService);
      const spy = jest.spyOn(jwtService, 'sign');
      spy.mockImplementationOnce(() => {
        return 'token';
      });
      mockUserService.find.mockResolvedValueOnce(user);
      mockPrismaService.forgotPassword.upsert.mockResolvedValueOnce(user);
      await authService.sendForgotPasswordLink('example@example.com');

      expect(mockMailService.sendResetPasswordLink).toHaveBeenCalled();
      expect(mockMailService.sendResetPasswordLink).toHaveBeenCalledWith(
        'example@example.com',
        'yourfrontend.com/auth/password/reset/token',
      );
      expect(mockPrismaService.forgotPassword.upsert).toHaveBeenCalled();
      expect(mockPrismaService.forgotPassword.upsert).toHaveBeenCalledWith({
        create: {
          email: 'example@example.com',
          token: 'token',
        },
        update: {
          email: 'example@example.com',
          token: 'token',
        },
        where: {
          email: 'example@example.com',
        },
      });
      expect(spy).toHaveBeenCalled();
      expect(spy).toHaveBeenCalledWith(
        { email: 'example@example.com' },
        {
          secret: config.get<string>('JWT_SECRET'),
          expiresIn: config.get<string>('EMAIL_JWT_EXPIRE_IN'),
        },
      );
    });
  });

  describe('resendVerifyEmail', () => {
    it('should resend verify e-mail', async () => {
      mockUserService.findById.mockResolvedValueOnce({
        ...user,
        id: '1',
      });
      await authService.resendVerifyEmail(1);
      expect(mockMailService.sendUserConfirmation).toHaveBeenCalled();
    });

    it('should throw an error when unexpected error occurs', async () => {
      mockUserService.findById.mockRejectedValueOnce(
        new InternalServerErrorException('Unexpected error'),
      );
      try {
        await authService.resendVerifyEmail(1);
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected error');
      }
    });
    it('should throw an error when user does not exist', async () => {
      mockUserService.findById.mockRejectedValueOnce(
        new BadRequestException('User does not exist'),
      );
      try {
        await authService.resendVerifyEmail(1);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Access Denied');
      }
    });
  });

  describe('resetPassword', () => {
    it('should throw BadRequestException when token no exist in Database', async () => {
      mockPrismaService.forgotPassword.findFirst.mockResolvedValueOnce(null);
      try {
        await authService.resetPassword('token', 'newPassword');
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Invalid token');
      }
    });

    it('should throw BadRequestException when token is invalid in JWT', async () => {
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        throw new BadRequestException('Invalid token');
      });

      mockPrismaService.forgotPassword.findFirst.mockResolvedValueOnce(
        'invalidToken',
      );
      try {
        await authService.resetPassword('token', 'newPassword');
      } catch (error) {
        expect(spy).toHaveBeenCalled();
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Invalid token');
      }
    });
    it('should throw BadRequestException when token email is not equal from database', async () => {
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        return {
          email: 'example@example.com',
        };
      });

      mockPrismaService.forgotPassword.findFirst.mockResolvedValueOnce({
        email: 'example2@example.com',
      });
      try {
        await authService.resetPassword('token', 'newPassword');
      } catch (error) {
        expect(spy).toHaveBeenCalled();
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('Invalid token');
      }
    });
    it('should throw BadRequestException when user no exist', async () => {
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        return {
          email: 'example@example.com',
        };
      });

      mockPrismaService.forgotPassword.findFirst.mockResolvedValueOnce({
        email: 'example@example.com',
      });

      mockUserService.find.mockRejectedValueOnce(
        new BadRequestException('User does not found'),
      );
      try {
        await authService.resetPassword('token', 'newPassword');
      } catch (error) {
        expect(spy).toHaveBeenCalled();
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
      }
    });
    it('should update user with new password', async () => {
      const jwtService = moduleRef.get(JwtService);
      const spy = jest.spyOn(jwtService, 'verify');
      spy.mockImplementationOnce(() => {
        return {
          email: 'example@example.com',
        };
      });

      mockPrismaService.forgotPassword.findFirst.mockResolvedValueOnce({
        email: 'example@example.com',
      });

      mockUserService.find.mockResolvedValue({
        ...user,
        id: 1,
      });

      mockUserService.updateUser.mockImplementationOnce((id) => {
        return {
          ...user,
          id,
          password: 'hashPassword',
        };
      });

      const updatedUser = await authService.resetPassword(
        'token',
        'newPassword',
      );
      expect(updatedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'test',
        password: 'hashPassword',
      });
      expect(spy).toHaveBeenCalled();
      expect(mockUserService.find).toHaveBeenCalled();
      expect(mockUserService.updateUser).toHaveBeenCalled();
      expect(mockPrismaService.forgotPassword.findFirst).toHaveBeenCalled();
    });
  });
});
