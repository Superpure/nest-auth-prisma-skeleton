import { Role } from '.prisma/client';

declare module 'express' {
  export interface Request {
    user: {
      userId: number;
      email: string;
      role: Role;
    };
  }
}