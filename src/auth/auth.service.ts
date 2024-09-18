import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { Role } from '.prisma/client';

@Injectable()
export class AuthService {

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService
  ) {}

  async registerCustomer(dto: RegisterUserDto) {
    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: hashedPassword,
        name: dto.name,
        lastName: dto.lastName,
        role: Role.CUSTOMER
      }
    });

    return this.generateToken(user.id, user.email, user.role);
  }

  async registerAdmin(dto: RegisterUserDto, creatorId: number) {
    const creator = await this.prisma.user.findUnique({
      where: {
        id: creatorId
      }
    });

    if (!creator || creator.role !== Role.ADMIN) {
      throw new UnauthorizedException('Only admins can create new admins');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        password: hashedPassword,
        name: dto.name,
        lastName: dto.lastName,
        role: Role.ADMIN
      }
    });

    return this.generateToken(user.id, user.email, user.role);
  }

  async login(dto: LoginUserDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    });

    if (!user || !await bcrypt.compare(dto.password, user.password)) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.generateToken(user.id, user.email, user.role);
  }

  generateToken(userId: number, email: string, role: string) {
    const payload = { sub: userId, email, role };
    return { access_token: this.jwtService.sign(payload) };
  }
}
