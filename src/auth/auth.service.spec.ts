import { ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import * as argon from 'argon2';
import { UserService } from '../user/user.service';
import { MailService } from '../mail/mail.service';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { User } from '@prisma/client';

const user = {
  email: 'test@gmail.com',
  password: 'super-secret-password',
  name: 'test',
};

describe('Auth Flow', () => {
  let authService: AuthService;
  let moduleRef: TestingModule;

  const mockPrismaService = {
    user: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
  };

  const mockMailService = {
    sendUserConfirmation: jest.fn(),
  };

  const mockUserService = {
    updateUser: jest.fn(),
    find: jest.fn(),
    findById: jest.fn(),
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
      mockPrismaService.user.create.mockResolvedValueOnce({
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

    it('should throw on duplicate user signup', async () => {
      let tokens: Tokens | undefined;
      mockPrismaService.user.create.mockRejectedValueOnce(
        new PrismaClientKnownRequestError('Error', 'P2002', '1'),
      );
      try {
        tokens = await authService.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('signin', () => {
    it('should throw if no existing user', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce(undefined);
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.signinLocal({
          email: user.email,
          password: user.password,
        });
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });

    it('should login', async () => {
      const password = await argon.hash(user.password);
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
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
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
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
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if unexpected error happens', async () => {
      mockPrismaService.user.findUnique.mockRejectedValueOnce(
        new Error('Unexpected error'),
      );
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.signinLocal({
          email: user.email,
          password: user.password,
        });
      } catch (error) {
        expect(error.message).toBe('Unexpected error');
      }

      expect(tokens).toBeUndefined();
    });
  });

  describe('logout', () => {
    it('should pass if call to non existent user', async () => {
      const result = await authService.logout(4);
      expect(result).toBeDefined();
    });
  });

  describe('refresh', () => {
    it('should throw if no existing user', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce(undefined);
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, '');
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });
    it('should throw if user logged out', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
        hashedRt: undefined,
      });
      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, '');
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if refresh token incorrect', async () => {
      const rt = 'hash';
      const hashedRt = await argon.hash(rt);
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
        hashedRt,
      });

      let tokens: Tokens | undefined;
      try {
        tokens = await authService.refreshTokens(1, rt + 'a');
      } catch (error) {
        expect(error.status).toBe(403);
      }

      expect(tokens).toBeUndefined();
    });

    it('should throw if refresh token incorrect', async () => {
      const rt = 'hash';
      const hashedRt = await argon.hash(rt);
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
        hashedRt,
      });

      const tokens = await authService.refreshTokens(1, rt);

      expect(tokens).toBeDefined();

      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
    });
  });

  describe('updateRtHash', () => {
    it('should call prisma.user.update', async () => {
      await authService.updateRtHash(1, 'hash');

      expect(mockPrismaService.user.update).toHaveBeenCalled();
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
      expect(spy).toHaveBeenCalledWith('token', { secret: 'at-secret' });
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
      expect(spy).toHaveBeenCalledWith('token', { secret: 'at-secret' });
    });
  });

  describe('changePassword', () => {
    it('should change password when the user is correct', async () => {
      const hashedPassword = await argon.hash('password');
      const userWithHashedPassword: User = {
        ...user,
        password: hashedPassword,
        id: 1,
        created_at: new Date(),
        updated_at: new Date(),
        hashedRt: '',
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
      const userWithHashedPassword: User = {
        ...user,
        password: hashedPassword,
        id: 1,
        created_at: new Date(),
        updated_at: new Date(),
        hashedRt: '',
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
        expect(error.message).toBe('Old password not correct');
      }
    });
  });
});
