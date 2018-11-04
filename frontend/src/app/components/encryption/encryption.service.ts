import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { environment as env } from '../../../environments/environment';
import { KeyType } from '../../models/key-type';

@Injectable({
  providedIn: 'root'
})
export class EncryptionService {

  constructor(private http: HttpClient) { }

  encrypt(keyType: KeyType, key: string, data: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('key', key);
      body.set('data', data);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded'),
        responseType: 'text' as 'text'
      };
      this.http.post(`${env.appBackend}/${keyType.toLowerCase()}/encrypt`, body.toString(), options)
        .subscribe(
          response => resolve(response),
          error => reject(error)
      );
    });
  }

  decrypt(keyType: KeyType, key: string, data: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('key', key);
      body.set('data', data);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded'),
        responseType: 'text' as 'text'
      };
      this.http.post(`${env.appBackend}/${keyType.toLowerCase()}/decrypt`, body.toString(), options)
        .subscribe(
          response => resolve(response),
          error => reject(error)
      );
    });
  }

}
