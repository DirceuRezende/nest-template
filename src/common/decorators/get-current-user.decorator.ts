import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayloadWithRt } from '../../auth/types';

export const getCurrentUser = (
  data: keyof JwtPayloadWithRt | undefined,
  context: ExecutionContext,
): string | number | JwtPayloadWithRt => {
  const request = context.switchToHttp().getRequest();
  const user: JwtPayloadWithRt = request.user;
  if (!data) return user;
  return user[data];
};

export const GetCurrentUser = createParamDecorator(getCurrentUser);
