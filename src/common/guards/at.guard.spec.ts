import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

import { AtGuard } from './at.guard';

describe('AuthenticatedGuard', () => {
  let atGuard: AtGuard;
  let mockReflector: jest.Mocked<Reflector>;

  beforeEach(() => {
    mockReflector = createMock<Reflector>();
    atGuard = new AtGuard(mockReflector);
  });

  it('should be defined', () => {
    expect(atGuard).toBeDefined();
  });

  describe('canActivate', () => {
    it('should return true when the route is public', () => {
      const mockContext = createMock<ExecutionContext>();
      mockReflector.getAllAndOverride.mockReturnValue(true);

      const canActivate = atGuard.canActivate(mockContext);

      expect(canActivate).toBe(true);
    });

    it('should return true when context is valid', async () => {
      const mockContext = createMock<ExecutionContext>();
      jest
        .spyOn(AuthGuard('jwt').prototype, 'canActivate')
        .mockImplementation(async () => {
          return true;
        });
      mockReflector.getAllAndOverride.mockReturnValue(false);

      const canActivate = await atGuard.canActivate(mockContext);
      expect(canActivate).toBe(true);
    });
  });
});
