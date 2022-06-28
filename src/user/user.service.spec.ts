import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ForbiddenException,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from '../prisma/prisma.service';
import { UserService } from './user.service';

const user = {
  email: 'test@gmail.com',
  password: 'super-secret-password',
  name: 'test',
};

describe('UserService', () => {
  let userService: UserService;
  let moduleRef: TestingModule;

  const mockPrismaService = {
    user: {
      create: jest.fn(),
      findUnique: jest.fn(),
      update: jest.fn(),
      updateMany: jest.fn(),
    },
    forgotPassword: {
      create: jest.fn(),
      findFirst: jest.fn(),
    },
  };

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      providers: [
        UserService,
        {
          provide: PrismaService,
          useValue: mockPrismaService,
        },
      ],
    }).compile();

    userService = moduleRef.get(UserService);
  });

  beforeEach(() => {
    jest.resetAllMocks();
    jest.clearAllMocks();
  });

  describe('findById', () => {
    it('should return an user', async () => {
      mockPrismaService.user.findUnique.mockImplementationOnce(({ where }) => {
        return { ...user, id: where.id };
      });
      const returnedUser = await userService.findById(1);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'test',
        password: 'super-secret-password',
      });
    });

    it('should throw a BadRequestException when user does not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce(undefined);
      try {
        await userService.findById(1);
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
        expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
      }
    });
  });

  describe('findByEmail', () => {
    it('should return an user', async () => {
      mockPrismaService.user.findUnique.mockImplementationOnce(({ where }) => {
        return { ...user, email: where.email, id: 1 };
      });
      const returnedUser = await userService.findByEmail('email@email.com');
      expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'email@email.com',
        id: 1,
        name: 'test',
        password: 'super-secret-password',
      });
    });

    it('should return undefined when User does not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce(undefined);

      const user = await userService.findByEmail('email@email.com');
      expect(user).toBeUndefined();
    });
  });
  describe('find', () => {
    it('should return a user with password', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
        ...user,
        id: 1,
      });
      const returnedUser = await userService.find({ where: { id: 1 } }, true);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'test',
        password: 'super-secret-password',
      });
    });
    it('should return a user without password', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
        ...user,
        id: 1,
      });
      const returnedUser = await userService.find({ where: { id: 1 } });
      expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'test',
      });
    });

    it('should throw a BadRequestException when User does not found', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce(undefined);
      try {
        await userService.findById(1);
      } catch (error) {
        expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
      }
    });
  });

  describe('createUser', () => {
    it('should return a user with password', async () => {
      mockPrismaService.user.findUnique.mockResolvedValueOnce({
        ...user,
        id: 1,
      });
      const returnedUser = await userService.find({ where: { id: 1 } }, true);
      expect(mockPrismaService.user.findUnique).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'test',
        password: 'super-secret-password',
      });
    });
    it('should return a user without password', async () => {
      mockPrismaService.user.create.mockResolvedValueOnce({
        ...user,
        id: 1,
      });
      const returnedUser = await userService.createUser({
        ...user,
      });
      expect(mockPrismaService.user.create).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'test',
        password: 'super-secret-password',
      });
    });

    it('should throw a ForbiddenException when Prisma User Create throw a PrismaClientKnownRequestError with code P2002', async () => {
      mockPrismaService.user.create.mockRejectedValueOnce(
        new PrismaClientKnownRequestError('Error', 'P2002', '1'),
      );
      try {
        await userService.createUser({
          ...user,
        });
      } catch (error) {
        expect(mockPrismaService.user.create).toHaveBeenCalled();
        expect(error).toBeInstanceOf(ForbiddenException);
        expect(error.message).toBe('Credentials incorrect');
      }
    });
    it('should throw a Error when Prisma User Create throw a Unexpected Error', async () => {
      mockPrismaService.user.create.mockRejectedValueOnce(
        new Error('Unexpected Error'),
      );
      try {
        await userService.createUser({
          ...user,
        });
      } catch (error) {
        expect(mockPrismaService.user.create).toHaveBeenCalled();
        expect(error).toBeInstanceOf(Error);
        expect(error.message).toBe('Unexpected Error');
      }
    });
  });

  describe('updateUser', () => {
    it('should update user', async () => {
      const spy = jest.spyOn(userService, 'findById');
      spy.mockResolvedValueOnce({
        ...user,
        id: 1,
        name: 'Test',
        created_at: new Date(),
        updated_at: new Date(),
        hashedRt: '',
        email_verified: false,
      });
      mockPrismaService.user.update.mockResolvedValueOnce({
        ...user,
        id: 1,
        name: 'Change Name',
      });
      const returnedUser = await userService.updateUser(1, {
        name: 'Change Name',
      });
      expect(mockPrismaService.user.update).toHaveBeenCalled();
      expect(returnedUser).toEqual({
        email: 'test@gmail.com',
        id: 1,
        name: 'Change Name',
        password: 'super-secret-password',
      });
    });
    it('should throw a InternalServerErrorException Prisma User Update throw a Error', async () => {
      mockPrismaService.user.update.mockImplementationOnce(() => {
        throw new Error('Unexpected Error');
      });
      try {
        await userService.updateUser(1, {
          name: 'Change Name',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected Error');
      }
    });

    it('should throw a BadRequestException when User does not found', async () => {
      const spy = jest.spyOn(userService, 'findById');
      spy.mockImplementationOnce(() => {
        throw new BadRequestException('User does not found');
      });
      try {
        await userService.updateUser(1, {
          name: 'Change Name',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
        expect(spy).toHaveBeenCalled();
      }
    });
  });

  describe('updateMany', () => {
    it('should update user', async () => {
      mockPrismaService.user.updateMany.mockResolvedValueOnce(1);
      const returnedUser = await userService.updateMany({
        data: {
          name: 'Change Name',
        },
        where: {
          id: 1,
        },
      });
      expect(mockPrismaService.user.updateMany).toHaveBeenCalled();
      expect(returnedUser).toBe(1);
    });

    it('should throw a InternalServerErrorException when prisma.user.update throw a Error', async () => {
      mockPrismaService.user.updateMany.mockImplementationOnce(() => {
        throw new Error('Unexpected Error');
      });
      try {
        await userService.updateMany({
          data: {
            name: 'Change Name',
          },
          where: {
            id: 1,
          },
        });
      } catch (error) {
        expect(error).toBeInstanceOf(InternalServerErrorException);
        expect(error.message).toBe('Unexpected Error');
      }
    });
    it('should throw a BadRequestException when User does not found', async () => {
      mockPrismaService.user.updateMany.mockImplementationOnce(() => {
        throw new PrismaClientKnownRequestError('Error', 'P2025', '1');
      });
      try {
        await userService.updateMany({
          data: {
            name: 'Change Name',
          },
          where: {
            id: 1,
          },
        });
      } catch (error) {
        expect(error).toBeInstanceOf(BadRequestException);
        expect(error.message).toBe('User does not found');
      }
    });
  });
});
