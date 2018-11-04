import { Injectable } from '@angular/core';
import { HttpClient, HttpParams, HttpHeaders } from '@angular/common/http';
import { environment as env } from '../../../environments/environment';
import { KeyType } from '../../models/key-type';

@Injectable({
  providedIn: 'root'
})
export class KeyGenerationService {

  constructor(private http: HttpClient) { }

  generateKey(keyType: KeyType, keySize: number) {
    return new Promise((resolve, reject) => {
      let options = {
        params: new HttpParams()
                    .set('keyLength', keySize.toString()),
        responseType: 'text' as 'text'
      };
      this.http.get(`${env.appBackend}/${keyType.toLowerCase()}/key`, options)
        .subscribe(
          response => resolve(response),
          error => reject(error)
      );
    });
  }

  generatePassword(alphaUpper: number, alphaLower: number, numeric: number, special: number) {
    return new Promise((resolve, reject) => {
      let options = {
        params: new HttpParams()
                    .set('alphaUpper', alphaUpper.toString())
                    .set('alphaLower', alphaLower.toString())
                    .set('numeric', numeric.toString())
                    .set('special', special.toString()),
        responseType: 'text' as 'text'
      };
      this.http.get(`${env.appBackend}/password`, options)
        .subscribe(
          response => resolve(response),
          error => reject(error)
      );
    });
  }

  persistKey(type: KeyType, name: string, value: string, token: string) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('name', name);
      body.set('type', type);
      body.set('value', value);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded')
                      .set('Authorization', `Bearer ${token}`)
      };
      this.http.post<any>(`${env.appBackend}/keys`, body.toString(), options)
        .subscribe(
          _ => resolve(),
          error => reject(error)
      );
    });
  }
}
