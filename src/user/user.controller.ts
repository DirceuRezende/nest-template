import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Put,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';

import { GetCurrentUserId } from '../common/decorators';
import { UserService } from './user.service';
import { UpdateUserDto, ResponseUserDto } from './dto';

@ApiBearerAuth()
@ApiTags('user')
@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Put('')
  @HttpCode(HttpStatus.OK)
  async update(
    @GetCurrentUserId() userId: number,
    @Body() dto: UpdateUserDto,
  ): Promise<ResponseUserDto> {
    if (!dto.email && !dto.name) {
      return;
    }
    const user = await this.userService.updateUser(userId, dto);
    const responseUser = {
      email: user.email,
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
