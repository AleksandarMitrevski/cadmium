import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { environment as env } from '../../../environments/environment';
import { HashType } from '../../models/hash-type';

@Injectable({
  providedIn: 'root'
})
export class HashingService {

  constructor(private http: HttpClient) { }

  calculateHash(contents: string, hashType: HashType) {
    return new Promise((resolve, reject) => {
      let body = new URLSearchParams();
      body.set('data', contents);
      let options = {
        headers: new HttpHeaders()
                      .set('Content-Type', 'application/x-www-form-urlencoded'),
        responseType: 'text' as 'text'
      };
      this.http.post(`${env.appBackend}/hashing/${hashType}`, body.toString(), options)
        .subscribe(
          response => resolve(response),
          error => reject(error)
      );
    });
  }
}
