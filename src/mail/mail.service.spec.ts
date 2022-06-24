import { Test, TestingModule } from '@nestjs/testing';
import { MailerService } from '@nestjs-modules/mailer';

import { MailService } from './mail.service';

describe('UserService', () => {
  let mailService: MailService;
  let moduleRef: TestingModule;

  const mockMailerService = {
    sendMail: jest.fn(),
  };

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      providers: [
        MailService,
        {
          provide: MailerService,
          useValue: mockMailerService,
        },
      ],
    }).compile();

    mailService = moduleRef.get(MailService);
  });

  beforeEach(() => {
    jest.resetAllMocks();
    jest.clearAllMocks();
  });

  describe('sendUserConfirmation', () => {
    it('should call sendMail from MailerService', async () => {
      await mailService.sendUserConfirmation(
        {
          email: 'test@email',
          name: 'test',
          password: 'test',
          id: 1,
          updated_at: new Date(),
          created_at: new Date(),
          hashedRt: 'test',
          email_verified: true,
        },
        'APP',
        'test url',
      );
      expect(mockMailerService.sendMail).toHaveBeenCalled();
    });
  });

  describe('sendResetPasswordLink', () => {
    it('should call sendMail from MailerService', async () => {
      await mailService.sendResetPasswordLink('test@email', 'APP');
      expect(mockMailerService.sendMail).toHaveBeenCalled();
    });
  });
});
