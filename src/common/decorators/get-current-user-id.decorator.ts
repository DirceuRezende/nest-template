import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from '../../auth/types';

export const getCurrentUserId = (
  _: undefined,
  context: ExecutionContext,
): number => {
  const request = context.switchToHttp().getRequest();
  const user = request.user as JwtPayload;
  return user.sub;
};

export const GetCurrentUserId = createParamDecorator(getCurrentUserId);
