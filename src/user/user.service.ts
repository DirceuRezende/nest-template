import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';
import { CreateUserDto } from 'src/auth/dto/create-user.dto';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon from 'argon2';

@Injectable()
export class UserService {
  constructor(private prismaService: PrismaService) {}

  async findById(id: number): Promise<User> {
    const user = await this.prismaService.user.findUnique({
      where: {
        id,
      },
    });
    if (!user) {
      throw new BadRequestException('User not found');
    }
    return user;
  }

  async find(options: any, withPassword = false): Promise<User> {
    const user = await this.prismaService.user.findUnique(options);
    if (!user) {
      throw new BadRequestException('User not found');
    }
    if (!withPassword) {
      delete user.password;
    }
    return user;
  }

  async createUser(dto: CreateUserDto): Promise<User> {
    const password = await argon.hash(dto.password);

    const newUser = await this.prismaService.user
      .create({
        data: {
          email: dto.email,
          password: password,
          name: dto.name,
        },
      })
      .catch((error) => {
        if (error instanceof PrismaClientKnownRequestError) {
          if (error.code === 'P2002') {
            throw new ForbiddenException('Credentials incorrect');
          }
        }

        throw error;
      });

    return newUser;
  }

  async updateUser(id: number, properties: any) {
    const user = await this.findById(id);

    try {
      const updatedUser = await this.prismaService.user.update({
        data: {
          ...user,
          ...properties,
        },
        where: {
          id,
        },
      });
      return updatedUser;
    } catch (error) {
      throw new InternalServerErrorException(error);
    }
  }
}
