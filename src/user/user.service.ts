import * as argon from 'argon2';
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { Prisma, User } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from '../auth/dto/create-user.dto';

export type UpdateProperties = Partial<Omit<User, 'updated_at' | 'created_at'>>;

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
      throw new BadRequestException('User does not found');
    }

    return user;
  }

  async findByEmail(email: string): Promise<User | undefined> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email,
      },
    });

    return user;
  }

  async find(
    options: Prisma.UserFindUniqueArgs,
    withPassword = false,
  ): Promise<User> {
    const user = await this.prismaService.user.findUnique(options);
    if (!user) {
      throw new BadRequestException('User does not found');
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

  async updateUser(id: number, properties: UpdateProperties): Promise<User> {
    try {
      if (properties.email) {
        const hasEmail = await this.prismaService.user.findFirst({
          where: {
            email: properties.email,
          },
        });
        if (hasEmail)
          throw new BadRequestException(
            'E-mail already used from another user!',
          );
      }
      const updatedUser = await this.prismaService.user.update({
        data: {
          ...properties,
        },
        where: {
          id,
        },
      });
      return updatedUser;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new BadRequestException('User does not found');
        }
      } else if (error.message === 'E-mail already used from another user!') {
        throw error;
      }

      throw new InternalServerErrorException(error);
    }
  }

  async updateMany(
    properties: Prisma.UserUpdateManyArgs,
  ): Promise<Prisma.BatchPayload> {
    try {
      const updatedUser = await this.prismaService.user.updateMany(properties);
      return updatedUser;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2025') {
          throw new BadRequestException('User does not found');
        }
      }
      throw new InternalServerErrorException(error);
    }
  }
}
