import { createMock } from '@golevelup/ts-jest';
import { ExecutionContext } from '@nestjs/common';
import { JwtPayloadWithRt } from 'src/auth/types';

import { getCurrentUser } from './get-current-user.decorator';

const user: JwtPayloadWithRt = {
  sub: 1,
  email: 'test@gmail.com',
  refreshToken: 'refreshToken',
};

describe('GetCurrentUserDecorator', () => {
  it('should be defined', () => {
    expect(getCurrentUser).toBeDefined();
  });

  describe('getCurrentUser', () => {
    it('should return JwtPayloadWithRt when user is authenticated', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({ user });

      const userReturned = getCurrentUser(undefined, mockContext);

      expect(userReturned).toEqual(user);
    });

    it('should return user email when user is authenticated and data is email', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({ user });

      const emailReturned = getCurrentUser('email', mockContext);

      expect(emailReturned).toBe(user.email);
    });

    it('should return user id when user is authenticated and data is sub', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({ user });

      const id = getCurrentUser('sub', mockContext);

      expect(id).toBe(user.sub);
    });

    it('should return user refreshToken when user is authenticated and data is refreshToken', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({ user });

      const refreshToken = getCurrentUser('refreshToken', mockContext);

      expect(refreshToken).toBe(user.refreshToken);
    });

    it('should throw a TypeError when user is not authenticated', () => {
      const mockContext = createMock<ExecutionContext>();
      mockContext.switchToHttp().getRequest.mockReturnValue({});
      try {
        getCurrentUser(undefined, mockContext);
      } catch (error) {
        expect(error).toBeInstanceOf(TypeError);
        expect(error.message).toBe(
          `Cannot read properties of undefined (reading 'sub')`,
        );
      }
    });
  });
});
