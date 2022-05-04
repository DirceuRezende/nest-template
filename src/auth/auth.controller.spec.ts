import { Test, TestingModule } from '@nestjs/testing';
import { User } from '@prisma/client';
import { decode } from 'jsonwebtoken';
import { PrismaService } from '../prisma/prisma.service';
import { AuthController } from './auth.controller';
import { Tokens } from './types';
import { MailService } from '../mail/mail.service';
import { ForbiddenException } from '@nestjs/common';
import { AppModule } from '../app.module';

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

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

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

    it('should pass if call to non existent user', async () => {
      const result = await authController.logout(4);
      expect(result).toBeDefined();
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
      await authController.logout(userFromDb!.id);

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
      await authController.logout(userId);

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
      await new Promise((resolve, reject) => {
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
});
