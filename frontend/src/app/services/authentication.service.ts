import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { User } from '../models/user';
import { environment as env } from '../../environments/environment';

@Injectable()
export class AuthenticationService {
  constructor(private http: HttpClient) { }

  login(username: string, password: string, rememberMe: boolean) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('username', username);
      body.set('password', password);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded'),
        responseType: 'text' as 'text'
      };
      this.http.post(`${env.appBackend}/auth/login`, body.toString(), options)
        .subscribe(
          token => {
            let user = new User(username, token);
            if(rememberMe){
              localStorage.setItem("user", JSON.stringify(user));
            }else{
              sessionStorage.setItem("user", JSON.stringify(user));
            }
            resolve();
          },
          error => reject(error)
      );
    });
  }

  register(username: string, password: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('username', username);
      body.set('password', password);
      let options = {
        headers: new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded')
      };
      this.http.post<any>(`${env.appBackend}/auth/register`, body.toString(), options)
        .subscribe(
          () => {
            // log user in
            let optionsLogin = {
              responseType: 'text' as 'text',
              ...options
            };
            this.http.post(`${env.appBackend}/auth/login`, body.toString(), optionsLogin)
              .subscribe(
                token => {
                  let user = new User(username, token);
                  sessionStorage.setItem("user", JSON.stringify(user));
                  resolve();
                },
                error => resolve()
              );
          },
          error => reject(error)
      );
    });
  }

  logout() {
    sessionStorage.removeItem('user');
    localStorage.removeItem('user');
  }

  isLoggedIn() {
    return this.getUser() !== null;
  }

  getUsername() {
    let user = this.getUser();
    if(user !== null){
      return user.username;
    }else{
      return null;
    }
  }

  changeUsername(username: string) {
    let user = this.getUser();
    if(user !== null){
      user.username = username;
    }
    
    // persist the change
    let ssUser = sessionStorage.getItem("user");
    if(typeof ssUser !== 'undefined' && ssUser !== null){
      sessionStorage.setItem("user", JSON.stringify(user));
    }
    
    let lsUser = localStorage.getItem("user");
    if(typeof lsUser !== 'undefined' && lsUser !== null){
      localStorage.setItem("user", JSON.stringify(user));
    }
  }

  getToken() {
    let user = this.getUser();
    if(user !== null){
      return user.token;
    }else{
      return null;
    }
  }

  private getUser() : User {
    let ssUser = sessionStorage.getItem("user");
    let lsUser = localStorage.getItem("user");
    if(typeof ssUser !== 'undefined' && ssUser !== null){
      return JSON.parse(ssUser) as User;
    }else if(typeof lsUser !== 'undefined' && lsUser !== null){
      return JSON.parse(lsUser) as User;
    }else{
      return null;
    }
  }

}
