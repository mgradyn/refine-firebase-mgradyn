import { Auth, User } from "firebase/auth";

declare interface IOriLoginArgs {
  email: string;
  password: string;
  remember: boolean;
}

declare interface ILoginArgs {
  clientId: string;
  client_id: string;
  credential: string;
  select_by: string;
}

declare interface IRegisterProps {
  setReCaptchaContainer: (ref: any) => void;
}

declare interface IRegisterArgs extends IOriLoginArgs {
  phone?: string;
  displayName?: string;
}

declare interface IUser extends Partial<User> {
  email: string;
  name?: string;
}

declare interface IAuthCallbacks {
  onRegister?: (user: User) => void;
  onLogin?: (user: User) => void;
  onLogout?: (auth: Auth) => any;
}

declare type TLogoutData = void | false | string;

export {
  IOriLoginArgs,
  ILoginArgs,
  IRegisterProps,
  IRegisterArgs,
  IUser,
  IAuthCallbacks,
  TLogoutData,
};
