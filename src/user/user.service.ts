import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { User } from '@prisma/client';

@Injectable()
export class UserService {
  constructor(private prismaService: PrismaService) {}

  async findById(id: number): Promise<User> {
    return this.prismaService.user.findUnique({
      where: {
        id,
      },
    });
  }

  async find(options: any, withPassword = false): Promise<User> | null {
    const user = await this.prismaService.user.findUnique(options);
    if (!user) {
      return;
    }
    if (!withPassword) {
      delete user.password;
    }
    return user;
  }

  async createUser(user: User): Promise<User> {
    const { name, email, password } = user;
    const newUser = await this.prismaService.user.create({
      data: {
        name,
        email,
        password,
      },
    });

    return newUser;
  }

  async updateUser(id: number, properties: any) {
    const user = await this.findById(id);

    if (!user) {
      throw new BadRequestException('User not found');
    }

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
