import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { KeyStoreService } from './key-store.service';
import { AuthenticationService } from '../../services/authentication.service';
import { KeyType } from '../../models/key-type';
import { Key } from '../../models/key';

@Component({
  selector: 'app-key-store',
  templateUrl: './key-store.component.html',
  styleUrls: ['./key-store.component.css']
})
export class KeyStoreComponent implements OnInit {

  constructor(private service: KeyStoreService, private auth: AuthenticationService, private router: Router) { }

  private readonly ITEMS_PER_PAGE = 10;

  keys: Array<Key> = null;
  showLoadingIndicator: boolean = false;
  page: number = 1;
  pagesTotal: number = 1;
  errors: Array<string> = [];

  ngOnInit() {
    this.loadKeys();
  }

  private loadKeys() {
    this.service.getKeys(this.auth.getToken(), this.page, this.ITEMS_PER_PAGE).then(
      data => {
        let keysArray = [];
        let keys = (data as any).keys as Array<any>;
        for(let i = 0, length = keys.length; i < length; ++i){
          let key = keys[i];
          keysArray.push(new Key(key.ID, key.Name, key.Type, key.Value, new Date(key.CreatedOn)));
        }
        this.keys = keysArray;
        this.pagesTotal = Math.ceil((data as any).total / this.ITEMS_PER_PAGE);
        this.showLoadingIndicator = false;
      },
      error => {
        //console.log(error);
        if(error.status == 401){
          this.auth.logout();
          this.router.navigate(["/login"]);
        }else if(error.status == 400 || error.status == 500){
          this.errors.push(error.statusText);
        }else{
          this.errors.push(error.message);
        }
        this.showLoadingIndicator = false;
      }
    );

    // show loader on timeout only to prevent flickering
    setTimeout(() => {
      if(this.keys == null && this.errors.length == 0)
        this.showLoadingIndicator = true;
    }, 500);
  }

  private onPaginationPrevClick() {
    if(this.page > 1){
      this.page--;
    }
    this.clearKeys();
    this.clearErrors();
    this.loadKeys();
    return false;
  }

  private onPaginationNextClick() {
    this.page++;
    this.clearKeys();
    this.clearErrors();
    this.loadKeys();
    return false;
  }

  private onKeyUse(key: Key) {
    this.setupEncryptionState(key.type, key.value);
    this.router.navigate(["/encryption"]);
  }

  private onKeyRename(key: Key, name: string) {
    this.service.renameKey(this.auth.getToken(), key.id, name).then(
      _ => {
        key.name = name;
      },
      error => {
        //console.log(error);
        if(error.status == 401){
          this.auth.logout();
          this.router.navigate(["/login"]);
        }else if(error.status == 400 || error.status == 500){
          this.errors.push(error.statusText);
        }else{
          this.errors.push(error.message);
        }
        this.showLoadingIndicator = false;
      }
    );
  }

  private onKeyDelete(key: Key) {
    this.service.deleteKey(this.auth.getToken(), key.id).then(
      _ => {
        this.clearKeys();
        this.clearErrors();
        this.loadKeys();
      },
      error => {
        //console.log(error);
        if(error.status == 401){
          this.auth.logout();
          this.router.navigate(["/login"]);
        }else if(error.status == 400 || error.status == 500){
          this.errors.push(error.statusText);
        }else{
          this.errors.push(error.message);
        }
        this.showLoadingIndicator = false;
      }
    );
  }

  // functionally identical to KeyGenerationComponent.setupEncryptionState()
  private setupEncryptionState(keyType: KeyType, key: string) {
    localStorage.setItem("encryption_key_type", keyType.toString());
    localStorage.setItem("encryption_operation", "encrypt");
    localStorage.removeItem("encryption_data");
    if(keyType !== KeyType.RSA){
      localStorage.setItem("encryption_key", key);
    }else{
      let keyParts = key.split("-----\n-----");
      if(keyParts.length === 2){
        keyParts[0] += "-----";
        keyParts[1] = "-----" + keyParts[1];
        localStorage.removeItem("encryption_key");
        localStorage.setItem("encryption_rsa_private", keyParts[0]);
        localStorage.setItem("encryption_rsa_public", keyParts[1]);
      }else{
        localStorage.setItem("encryption_key", key);
      }
    }
  }

  private clearKeys() {
    this.keys = null;
  }

  private clearErrors() {
    this.errors = [];
  }
}
