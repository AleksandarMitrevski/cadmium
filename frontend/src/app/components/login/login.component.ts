import { Component, OnInit, ViewChild, ElementRef, Renderer2 } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticationService } from '../../services/authentication.service';

enum LoginMode {
  Login,
  Register
}

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements OnInit {
  loginModes = LoginMode;
  mode : LoginMode = LoginMode.Login;
  private errors : Array<string> = [];

  private login = { username: "", password: ""};
  private register = { username: "", password: "", passwordRepeat: "" };

  @ViewChild('loginInputUsername') loginUsernameElement: ElementRef;
  @ViewChild('loginInputPassword') loginPasswordElement: ElementRef;
  @ViewChild('loginInputRememberMe') loginRememberMeElement: ElementRef;
  @ViewChild('registerInputUsername') registerUsernameElement: ElementRef;
  @ViewChild('registerInputPassword') registerPasswordElement: ElementRef;
  @ViewChild('registerInputPasswordRepeat') registerPasswordRepeatElement: ElementRef;

  constructor(private router: Router, private auth: AuthenticationService, private renderer: Renderer2) { }

  ngOnInit() {
  }

  onLogin() {
    this.clearLoginErrors();
    this.validateLogin();
    if(this.errors.length == 0){
      this.auth.login(this.login.username, this.login.password, this.loginRememberMeElement.nativeElement.checked).then(
        _ => {
          if(sessionStorage.getItem("login_redirect_to")){
            let destination = sessionStorage.getItem("login_redirect_to");
            sessionStorage.removeItem("login_redirect_to");
            this.router.navigate([`/${destination}`]);
          }else{
            this.router.navigate(['/encryption']);
          }
        },
        error => {
          console.log(error);
          if(error.status == 401){
            this.errors.push("Invalid credentials.");
          }else{
            this.errors.push(error.message);
          }
        }
      );
    }
  }

  onRegister() {
    this.clearRegisterErrors();
    this.validateRegister();
    if(this.errors.length == 0){
      this.auth.register(this.register.username, this.register.password).then(
        _ => {
          if(sessionStorage.getItem("login_redirect_to")){
            let destination = sessionStorage.getItem("login_redirect_to");
            sessionStorage.removeItem("login_redirect_to");
            this.router.navigate([`/${destination}`]);
          }else{
            this.router.navigate(['/encryption']);
          }
        },
        error => {
          //console.log(error);
          if(error.status == 400){
            this.errors.push("Username is taken.");
          }else{
            this.errors.push(error.message);
          }
        }
      );
    }
  }

  private clearLoginErrors() {
    this.errors = [];
    this.removeInputElementInvalidClasses(this.loginUsernameElement.nativeElement);
    this.removeInputElementInvalidClasses(this.loginPasswordElement.nativeElement);
  }

  private validateLogin() {
    if(this.login.username.length == 0){
      this.errors.push("Username is empty.");
      this.setInputElementInvalidClasses(this.loginUsernameElement.nativeElement);
    }
    if(this.login.password.length == 0){
      this.errors.push("Password is empty.");
      this.setInputElementInvalidClasses(this.loginPasswordElement.nativeElement);
    }
  }

  private clearRegisterErrors() {
    this.errors = [];
    this.removeInputElementInvalidClasses(this.registerUsernameElement.nativeElement);
    this.removeInputElementInvalidClasses(this.registerPasswordElement.nativeElement);
    this.removeInputElementInvalidClasses(this.registerPasswordRepeatElement.nativeElement);
  }

  private validateRegister() {
    if(this.register.username.length == 0){
      this.errors.push("Username is empty.");
      this.setInputElementInvalidClasses(this.registerUsernameElement.nativeElement);
    }
    if(this.register.password.length == 0){
      this.errors.push("Password is empty.");
      this.setInputElementInvalidClasses(this.registerPasswordElement.nativeElement);
      this.setInputElementInvalidClasses(this.registerPasswordRepeatElement.nativeElement);
    }else if(this.register.password != this.register.passwordRepeat){
      this.errors.push("Passwords do not match.");
      this.setInputElementInvalidClasses(this.registerPasswordElement.nativeElement);
      this.setInputElementInvalidClasses(this.registerPasswordRepeatElement.nativeElement);
    }
  }

  private setInputElementInvalidClasses(element: any) {
    this.renderer.addClass(element, "was-validated");
    this.renderer.addClass(element, "is-invalid");
  }

  private removeInputElementInvalidClasses(element: any) {
    this.renderer.removeClass(element, "was-validated");
    this.renderer.removeClass(element, "is-invalid");
  }

  switchToMode(mode : LoginMode) {
    this.errors = [];
    this.mode = mode;
  }

}
