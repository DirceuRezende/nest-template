import { createMock } from '@golevelup/ts-jest';
import { ForbiddenException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../types';
import { Request } from 'express';

import { RtStrategy } from './rt.strategy';

describe('RtStrategy', () => {
  let rtStrategy: RtStrategy;
  const mockJwtPayload: JwtPayload = {
    sub: 1,
    email: 'test@email.com',
  };

  beforeEach(() => {
    rtStrategy = new RtStrategy(createMock<ConfigService>());
  });

  it('should be defined', () => {
    expect(rtStrategy).toBeDefined();
  });

  describe('validate', () => {
    it('should return JwtPayloadWithRt when request has a valid bearer token', () => {
      const mockRequest = createMock<Request>();
      mockRequest.get.mockReturnValue('Bearer token');

      const validate = rtStrategy.validate(mockRequest, mockJwtPayload);

      expect(validate).toEqual({ ...mockJwtPayload, refreshToken: 'token' });
    });

    it('should throw ForbiddenException when request has an invalid bearer token', () => {
      const mockRequest = createMock<Request>();
      mockRequest.get.mockReturnValue('Bearer');

      try {
        rtStrategy.validate(mockRequest, mockJwtPayload);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Refresh token malformed');
      }
    });

    it('should throw ForbiddenException when request has not a bearer token', () => {
      const mockRequest = createMock<Request>();
      mockRequest.get.mockReturnValue('');

      try {
        rtStrategy.validate(mockRequest, mockJwtPayload);
      } catch (error) {
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Refresh token malformed');
      }
    });
  });
});
