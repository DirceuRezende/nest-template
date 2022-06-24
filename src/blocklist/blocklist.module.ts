import { CacheModule, Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as redisStore from 'cache-manager-redis-store';
import { BlockListService } from './blocklist.service';

@Module({
  imports: [
    CacheModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        store: redisStore,
        host: configService.get<string>('REDIS_HOST'),
        port: configService.get<string>('REDIS_PORT'),
        auth_pass: configService.get<string>('REDIS_PASSWORD'),
        ttl: 60 * 3600 * 1000,
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [BlockListService],
  exports: [BlockListModule, BlockListService, CacheModule],
})
export class BlockListModule {}
