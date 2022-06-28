import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, CACHE_MODULE_OPTIONS } from '@nestjs/common';
import { decode } from 'jsonwebtoken';
import { PrismaService } from '../prisma/prisma.service';
import { UserController } from './user.controller';
import { AppModule } from '../app.module';
import { AuthController } from '../auth/auth.controller';
import { MailService } from '../mail/mail.service';

const user = {
  email: 'test@gmail.com',
  password: 'super-secret-password',
  name: 'test',
};

describe('User Flow', () => {
  let prisma: PrismaService;
  let userController: UserController;
  let authController: AuthController;
  let mailService: MailService;
  let moduleRef: TestingModule;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    })
      .overrideProvider(CACHE_MODULE_OPTIONS)
      .useValue({
        ttl: 10,
      })
      .compile();

    prisma = moduleRef.get(PrismaService);
    userController = moduleRef.get(UserController);
    authController = moduleRef.get(AuthController);
    mailService = moduleRef.get(MailService);
    const spy = jest.spyOn(mailService, 'sendUserConfirmation');
    spy.mockReturnValue(Promise.resolve());
  });

  afterAll(async () => {
    await moduleRef.close();
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    await prisma.cleanDatabase();
  });

  describe('update', () => {
    it('should update user', async () => {
      const tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const decoded = decode(tokens.refresh_token);
      const userId = Number(decoded?.sub);

      const updateResponse = await userController.update(userId, {
        name: 'Updated name',
        email: 'update@email.com',
      });

      expect(updateResponse).toEqual({
        email: 'update@email.com',
        name: 'Updated name',
      });
    });

    it('should throw a ForbiddenException when user does not found', async () => {
      try {
        const tokens = await authController.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });

        const decoded = decode(tokens.refresh_token);
        const userId = Number(decoded?.sub);

        await userController.update(userId + 1, {
          name: 'updated name',
          email: 'update@email.com',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
      }
    });

    it('should throw a ForbiddenException when user does not found', async () => {
      try {
        const tokens = await authController.signupLocal({
          email: user.email,
          password: user.password,
          name: user.name,
        });

        const decoded = decode(tokens.refresh_token);
        const userId = Number(decoded?.sub);

        await userController.update(userId, {
          name: 'updated name',
          email: user.email,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('E-mail already used from another user!');
      }
    });

    it('should return undefined when name and e-mail are empty', async () => {
      const r = await userController.update(1, {});
      expect(r).toBeUndefined();
    });
  });

  describe('getUser', () => {
    it('should return user info', async () => {
      const tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const decoded = decode(tokens.refresh_token);
      const userId = Number(decoded?.sub);

      const userResponse = await userController.getUser(userId);

      expect(userResponse).toEqual({
        email: user.email,
        email_verified: false,
        name: user.name,
      });
    });

    it('should throw a BadRequestException when user does not found', async () => {
      const tokens = await authController.signupLocal({
        email: user.email,
        password: user.password,
        name: user.name,
      });

      const decoded = decode(tokens.refresh_token);
      const userId = Number(decoded?.sub);
      try {
        await userController.getUser(userId + 1);
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
      }
    });
  });
});
