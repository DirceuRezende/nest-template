import { ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

import { BlockListService } from '../../blocklist/blocklist.service';

@Injectable()
export class AtGuard extends AuthGuard('jwt') {
  constructor(
    private reflector: Reflector,
    private blockListService: BlockListService,
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<any> {
    const isPublic = this.reflector.getAllAndOverride('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;
    const request = await context.switchToHttp().getRequest();

    const token = request.headers.authorization.split(' ')[1];

    const isBlocked = await this.blockListService.get(`block:${token}`);

    if (isBlocked !== null) {
      return false;
    }

    return super.canActivate(context);
  }
}
