import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const configService = app.get(ConfigService);
  const ENABLE_LOGGING = configService.get('ENABLE_LOGGING') || false;

  app.useGlobalPipes(new ValidationPipe());
  if (ENABLE_LOGGING) {
    app.useLogger(app.get(WINSTON_MODULE_NEST_PROVIDER));
  }
  await app.listen(3333);
}
bootstrap();
