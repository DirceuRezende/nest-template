import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Put,
} from '@nestjs/common';

import { GetCurrentUserId } from '../common/decorators';
import { UserService } from './user.service';
import { UpdateUserDto } from './dto/update-user.dto';

import { ResponseUserDto } from './dto/reponse-user.dto';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Put('')
  @HttpCode(HttpStatus.NO_CONTENT)
  async update(
    @GetCurrentUserId() userId: number,
    @Body() dto: UpdateUserDto,
  ): Promise<ResponseUserDto> {
    const user = await this.userService.updateUser(userId, dto);
    const responseUser = {
      email: user.email,
      email_verified: user.email_verified,
      name: user.name,
    };
    return responseUser;
  }

  @Get('whoami')
  @HttpCode(HttpStatus.OK)
  async getUser(@GetCurrentUserId() userId: number): Promise<ResponseUserDto> {
    const user = await this.userService.findById(userId);
    const responseUser = {
      email: user.email,
      email_verified: user.email_verified,
      name: user.name,
    };
    return responseUser;
  }
}
