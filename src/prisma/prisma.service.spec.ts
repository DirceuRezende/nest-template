import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { PrismaClient } from '@prisma/client';
import { PrismaService } from './prisma.service';

describe('UserService', () => {
  let prismaService: PrismaService;
  let moduleRef: TestingModule;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      providers: [PrismaService, ConfigService],
    }).compile();

    prismaService = moduleRef.get(PrismaService);
  });

  beforeEach(() => {
    jest.resetAllMocks();
    jest.clearAllMocks();
  });

  describe('onModuleInit', () => {
    it('should call $connect from PrismaClient', async () => {
      const spy = jest.spyOn(PrismaClient.prototype, '$connect');
      spy.mockResolvedValueOnce();
      await prismaService.onModuleInit();
      expect(spy).toHaveBeenCalled();
    });
  });

  describe('onModuleDestroy', () => {
    it('should call $connect from PrismaClient', async () => {
      const spy = jest.spyOn(PrismaClient.prototype, '$disconnect');
      spy.mockResolvedValueOnce();
      await prismaService.onModuleDestroy();
      expect(spy).toHaveBeenCalled();
    });
  });

  describe('cleanDatabase', () => {
    it('should clean database', async () => {
      const clear = await prismaService.cleanDatabase();
      await expect(clear).toBeTruthy();
    });
    it('should not clean database', async () => {
      const configService = moduleRef.get(ConfigService);
      jest.spyOn(configService, 'get').mockReturnValueOnce('production');
      const clear = await prismaService.cleanDatabase();
      await expect(clear).toBeFalsy();
    });
  });
});
