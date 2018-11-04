import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { User } from '../../models/user';
import { environment as env } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class SettingsService {
  constructor(private http: HttpClient) { }

  changeUsername(token: string, username: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('username', username);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded')
                      .set('Authorization', `Bearer ${token}`)
      };
      this.http.post<any>(`${env.appBackend}/auth/change-username`, body.toString(), options)
        .subscribe(
          response => resolve(),
          error => reject(error)
      );
    });
  }

  changePassword(token: string, password: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('password', password);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded')
                      .set('Authorization', `Bearer ${token}`)
      };
      this.http.post<any>(`${env.appBackend}/auth/change-password`, body.toString(), options)
        .subscribe(
          response => resolve(),
          error => reject(error)
      );
    });
  }
}
