import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto, AuthSignInDto } from './dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

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

    return user;
  }
}
