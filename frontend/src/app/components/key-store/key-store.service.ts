import { Injectable } from '@angular/core';
import { HttpClient, HttpParams, HttpHeaders } from '@angular/common/http';
import { environment as env } from '../../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class KeyStoreService {

  constructor(private http: HttpClient) { }

  getKeys(token: string, page: number, itemsPerPage: number) {
    return new Promise((resolve, reject) => {
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded')
                      .set('Authorization', `Bearer ${token}`),
        params: new HttpParams()
                      .set('page', page.toString())
                      .set('itemsPerPage', itemsPerPage.toString())
      };
      this.http.get<any>(`${env.appBackend}/keys`, options)
        .subscribe(
          response => resolve(response),
          error => reject(error)
      );
    });
  }

  renameKey(token: string, keyId: number, name: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('name', name);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded')
                      .set('Authorization', `Bearer ${token}`)
      };
      this.http.post(`${env.appBackend}/keys/${keyId.toString()}`, body.toString(), options)
        .subscribe(
          _ => resolve(),
          error => reject(error)
      );
    });
  }

  deleteKey(token: string, keyId: number) {
    return new Promise((resolve, reject) => {
      let options = {
        headers: new HttpHeaders()
                      .set('Authorization', `Bearer ${token}`)
      };
      this.http.delete(`${env.appBackend}/keys/${keyId.toString()}`, options)
        .subscribe(
          _ => resolve(),
          error => reject(error)
      );
    });
  }
}
