import {
  IsEmail,
  IsNotEmpty,
} from 'class-validator';

export class AuthSignInDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  password: string;
}
