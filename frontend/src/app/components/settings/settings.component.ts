import { Component, OnInit, ViewChild, ElementRef, Renderer2 } from '@angular/core';
import { Router } from '@angular/router';
import { AuthenticationService } from '../../services/authentication.service';
import { SettingsService } from './settings.service';

@Component({
  selector: 'app-settings',
  templateUrl: './settings.component.html',
  styleUrls: ['./settings.component.css']
})
export class SettingsComponent implements OnInit {

  constructor(private service: SettingsService, private auth: AuthenticationService, private renderer: Renderer2, private router: Router) {
    this.username = auth.getUsername();
  }

  username: string = "";
  password: string = "";
  passwordRepeat: string = "";

  successUsername: boolean = false;
  successPassword: boolean = false;
  errorsUsername: Array<string> = [];
  errorsPassword: Array<string> = [];

  @ViewChild('usernameElement') usernameElement: ElementRef;
  @ViewChild('passwordElement') passwordElement: ElementRef;
  @ViewChild('passwordRepeatElement') passwordRepeatElement: ElementRef;

  ngOnInit() {
  }

  onChangeUsername() {
    this.hideSuccessMessages();
    this.clearUsernameErrors();
    this.validateUsername();
    if(this.errorsUsername.length == 0){
      this.service.changeUsername(this.auth.getToken(), this.username).then(
        _ => {
          this.auth.changeUsername(this.username);
          this.successUsername = true;
        },
        error => {
          //console.log(error);
          if(error.status == 401){
            this.auth.logout();
            this.router.navigate(["/login"]);
          }else{
            this.errorsUsername.push(error.message);
          }
        }
      );
    }
  }

  onChangePassword() {
    this.hideSuccessMessages();
    this.clearPasswordErrors();
    this.validatePassword();
    if(this.errorsPassword.length == 0){
      this.service.changePassword(this.auth.getToken(), this.password).then(
        _ => {
          this.successPassword = true;
        },
        error => {
          //console.log(error);
          if(error.status == 401){
            this.auth.logout();
            this.router.navigate(["/login"]);
          }else{
            this.errorsPassword.push(error.message);
          }
        }
      );
    }
  }

  private clearUsernameErrors() {
    this.errorsUsername = [];
    this.removeInputElementInvalidClasses(this.usernameElement.nativeElement);
  }

  private validateUsername() {
    if(this.username.length == 0){
      this.errorsUsername.push("Username is empty.");
      this.setInputElementInvalidClasses(this.usernameElement.nativeElement);
    }else if(this.username === this.auth.getUsername()){
      this.errorsUsername.push("Desired username is identical to current.");
      this.setInputElementInvalidClasses(this.usernameElement.nativeElement);
    }
  }

  private clearPasswordErrors() {
    this.errorsPassword = [];
    this.removeInputElementInvalidClasses(this.passwordElement.nativeElement);
    this.removeInputElementInvalidClasses(this.passwordRepeatElement.nativeElement);
  }

  private validatePassword() {
    if(this.password.length == 0){
      this.errorsPassword.push("Password is empty.");
      this.setInputElementInvalidClasses(this.passwordElement.nativeElement);
      this.setInputElementInvalidClasses(this.passwordRepeatElement.nativeElement);
    }else if(this.password !== this.passwordRepeat){
      this.errorsPassword.push("Passwords do not match.");
      this.setInputElementInvalidClasses(this.passwordElement.nativeElement);
      this.setInputElementInvalidClasses(this.passwordRepeatElement.nativeElement);
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

  private hideSuccessMessages() {
    this.successUsername = false;
    this.successPassword = false;
  }

}
