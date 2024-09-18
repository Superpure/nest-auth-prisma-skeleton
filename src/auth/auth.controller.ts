import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterUserDto } from './dto/register-user.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RolesGuard } from './guards/roles.guard';
import { Roles } from './decorators/roles.decorator';
import { LoginUserDto } from './dto/login-user.dto';
import { Request } from 'express';

@Controller('auth')
export class AuthController {
  constructor( private readonly authService: AuthService) {}

  @Post('register/customer')
  registerCustomer(@Body() dto: RegisterUserDto) {
    return this.authService.registerCustomer(dto);
  }

  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  @Post('register/admin')
  registerAdmin(@Body() dto: RegisterUserDto, @Req() req: Request) {
    return this.authService.registerAdmin(dto, req.user.userId);
  }

  @Get('login')
  login(@Body() dto: LoginUserDto) {
    return this.authService.login(dto);
  }
}
