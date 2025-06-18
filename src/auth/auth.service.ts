import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto, AuthSignInDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);

      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          firstName: dto.firstName,
          lastName: dto.lastName,
          hash,
        },
        select: {
          id: true,
          firstName: true,
          lastName: true,
          email: true,
        },
      });

      return user;
    } catch (error) {
      throw new ForbiddenException(
        'User failed to sign up.',
      );
    }
  }

  async signin(dto: AuthSignInDto) {
    console.log({ dto });
    const user =
      await this.prisma.user.findUnique({
        where: {
          email: dto.email,
        },
      });

    if (!user) {
      throw new ForbiddenException(
        'User not found',
      );
    }

    const pwMatch = await argon.verify(
      user.hash,
      dto.password,
    );
    if (!pwMatch) {
      throw new ForbiddenException(
        'Incorrect credentials',
      );
    }

    return this.signInToken(user.id, user.email);
  }

  async signInToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret,
      },
    );

    return {
      access_token: token,
    };
  }
}
