import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext } from '@nestjs/common';

import { getCurrentUserId } from './get-current-user-id.decorator';

describe('GetCurrentUserIdDecorator', () => {
  it('should be defined', () => {
    expect(getCurrentUserId).toBeDefined();
  });

  describe('getCurrentUserId', () => {
    it('should return id when user is authenticated', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({
        user: {
          sub: 1,
        },
      });

      const idUser = getCurrentUserId(undefined, mockContext);

      expect(idUser).toBe(1);
    });

    it('should throw a TypeError when user is not authenticated', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({});
      try {
        getCurrentUserId(undefined, mockContext);
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect(error.message).toBe(
          `Cannot read properties of undefined (reading 'sub')`,
        );
      }
    });
  });
});
