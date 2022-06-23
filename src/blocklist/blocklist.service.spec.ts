import { CacheModule } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test, TestingModule } from '@nestjs/testing';
import { BlockListService } from './blocklist.service';

describe('BlockListService', () => {
  let moduleRef: TestingModule;
  let blockListService: BlockListService;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [CacheModule.register({})],
      providers: [BlockListService, ConfigService],
    }).compile();

    blockListService = moduleRef.get(BlockListService);
  });

  beforeEach(() => {
    jest.resetAllMocks();
    jest.clearAllMocks();
  });

  describe('get', () => {
    it('should return undefined when key is invalid', async () => {
      const r = await blockListService.get('block:key');
      await expect(r).toBeUndefined();
    });

    it('should return the value of key', async () => {
      await blockListService.set('block:key', {
        id: 1,
      });
      const r = await blockListService.get('block:key');
      await expect(r).toEqual({ id: 1 });
    });
  });

  describe('set', () => {
    it('should add new key and value', async () => {
      await blockListService.set('block:key', {
        id: 1,
      });
      const r = await blockListService.get('block:key');
      await expect(r).toEqual({ id: 1 });
    });
  });

  describe('del', () => {
    it('should return undefined after del the key', async () => {
      await blockListService.set('block:key', {
        id: 1,
      });
      await blockListService.del('block:key');
      const r = await blockListService.get('block:key');
      await expect(r).toBeUndefined();
    });
  });
});
