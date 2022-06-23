import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { BlockListService } from 'src/blocklist/blocklist.service';

import { AtGuard } from './at.guard';

describe('AuthenticatedGuard', () => {
  let atGuard: AtGuard;
  let mockReflector: jest.Mocked<Reflector>;
  let mockBlockListService: jest.Mocked<BlockListService>;

  beforeEach(() => {
    mockReflector = createMock<Reflector>();
    mockBlockListService = createMock<BlockListService>();
    atGuard = new AtGuard(mockReflector, mockBlockListService);
  });

  it('should be defined', () => {
    expect(atGuard).toBeDefined();
  });

  describe('canActivate', () => {
    it('should return true when the route is public', async () => {
      const mockContext = createMock<ExecutionContext>();
      mockReflector.getAllAndOverride.mockReturnValue(true);

      const canActivate = await atGuard.canActivate(mockContext);

      expect(canActivate).toBe(true);
    });

    it('should return true when context is valid and token is not blocked', async () => {
      const mockContext = createMock<ExecutionContext>();
      jest
        .spyOn(AuthGuard('jwt').prototype, 'canActivate')
        .mockImplementation(async () => {
          return true;
        });
      mockReflector.getAllAndOverride.mockReturnValue(false);
      mockBlockListService.get.mockResolvedValue(null);
      mockContext.switchToHttp().getRequest.mockImplementation(async () => {
        return {
          headers: {
            authorization: 'Bearer token',
          },
        };
      });
      const canActivate = await atGuard.canActivate(mockContext);
      expect(canActivate).toBeTruthy();
    });
    it('should return false when context is valid but token is blocked', async () => {
      const mockContext = createMock<ExecutionContext>();
      jest
        .spyOn(AuthGuard('jwt').prototype, 'canActivate')
        .mockImplementation(async () => {
          return true;
        });
      mockReflector.getAllAndOverride.mockReturnValue(false);
      mockBlockListService.get.mockResolvedValue(() => ({ id: 1 }));
      mockContext.switchToHttp().getRequest.mockImplementation(async () => {
        return {
          headers: {
            authorization: 'Bearer token',
          },
        };
      });
      const canActivate = await atGuard.canActivate(mockContext);
      expect(canActivate).toBeFalsy();
    });
  });
});
