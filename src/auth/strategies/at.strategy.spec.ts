import { createMock } from '@golevelup/ts-jest';
import { ConfigService } from '@nestjs/config';
import { JwtPayload } from '../types';
import { Request } from 'express';

import { AtStrategy } from './at.strategy';

describe('RtStrategy', () => {
  let atStrategy: AtStrategy;
  const mockJwtPayload: JwtPayload = {
    sub: 1,
    email: 'test@email.com',
  };

  beforeEach(() => {
    atStrategy = new AtStrategy(createMock<ConfigService>());
  });

  it('should be defined', () => {
    expect(atStrategy).toBeDefined();
  });

  describe('validate', () => {
    it('should return JwtPayload', () => {
      const mockRequest = createMock<Request>();
      mockRequest.get.mockReturnValue('Bearer token');

      const validate = atStrategy.validate(mockJwtPayload);

      expect(validate).toEqual(mockJwtPayload);
    });
  });
});
