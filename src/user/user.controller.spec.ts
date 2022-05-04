import { Test, TestingModule } from '@nestjs/testing';
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
    }).compile();

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

  describe('update', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

    it('should signup', async () => {
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
        email_verified: false,
        name: 'Updated name',
      });
    });
  });

  describe('getUser', () => {
    beforeAll(async () => {
      await prisma.cleanDatabase();
    });

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
  });
});
