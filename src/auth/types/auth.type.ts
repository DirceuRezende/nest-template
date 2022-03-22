import { Tokens } from './tokens.type';

export type UserLoginInfo = {
  email: string;
  name: string;
};

export type Auth = {
  user: UserLoginInfo;
} & Tokens;
