import { PrismaClient } from '.prisma/client';
import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  constructor(private config: ConfigService) {
    const url = config.get<string>('DATABASE_URL');

    super({
      datasources: {
        db: {
          url,
        },
      },
    });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  async cleanDatabase(): Promise<boolean> {
    if (this.config.get<string>('NODE_ENV') === 'production') return false;

    // teardown logic
    const allKeys = Object.keys(this);

    const keys = [
      '_baseDmmf',
      '_middlewares',
      '_transactionId',
      '_rejectOnNotFound',
      '_clientVersion',
      '_activeProvider',
      '_clientEngineType',
      '_errorFormat',
      '_dmmf',
      '_previewFeatures',
      '_engineConfig',
      '_engine',
      '_fetcher',
      '_dataProxy',
      '_metrics',
      'config',
    ];
    const modelNames = allKeys.filter((property) => !keys.includes(property));
    await Promise.all(
      modelNames.map((modelName) => {
        return this[modelName].deleteMany();
      }),
    );

    return true;
  }
}
