import { Component, OnInit, AfterViewInit, ViewChild, ElementRef, Renderer2 } from '@angular/core';
import { KeyGenerationService } from './key-generation.service';
import { KeyType } from '../../models/key-type';
import { AuthenticationService } from '../../services/authentication.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-key-generation',
  templateUrl: './key-generation.component.html',
  styleUrls: ['./key-generation.component.css']
})
export class KeyGenerationComponent implements OnInit, AfterViewInit {

  constructor(private renderer: Renderer2, private service: KeyGenerationService, private auth: AuthenticationService, private router: Router) { }

  keyTypes = KeyType;
  selectedKeyType: KeyType = KeyType.RSA;
  persistVisible: boolean = false;

  // need to persisted on change, for user convenience
  private _keySize: string = "0";
  get keySize(): string {
    return this._keySize;
  }
  set keySize(keySize: string) {
    this._keySize = keySize;
    localStorage.setItem("keygen_key_size", keySize);
  }
  private _passwordAlphaUpper: string = "0";
  get passwordAlphaUpper(): string {
    return this._passwordAlphaUpper;
  }
  set passwordAlphaUpper(passwordAlphaUpper: string) {
    this._passwordAlphaUpper = passwordAlphaUpper;
    localStorage.setItem("keygen_password_alpha_upper", passwordAlphaUpper);
  }
  private _passwordAlphaLower: string = "0";
  get passwordAlphaLower(): string {
    return this._passwordAlphaLower;
  }
  set passwordAlphaLower(passwordAlphaLower: string) {
    this._passwordAlphaLower = passwordAlphaLower;
    localStorage.setItem("keygen_password_alpha_lower", passwordAlphaLower);
  }
  private _passwordNumeric: string = "0";
  get passwordNumeric(): string {
    return this._passwordNumeric;
  }
  set passwordNumeric(passwordNumeric: string) {
    this._passwordNumeric = passwordNumeric;
    localStorage.setItem("keygen_password_numeric", passwordNumeric);
  }
  private _passwordSpecial: string = "0";
  get passwordSpecial(): string {
    return this._passwordSpecial;
  }
  set passwordSpecial(passwordSpecial: string) {
    this._passwordSpecial = passwordSpecial;
    localStorage.setItem("keygen_password_special", passwordSpecial);
  }
  result: string = "";
  errorsGenerator: Array<string> = [];
  private keyName: string = "";
  private errorsPersistence: Array<string> = [];
  private persistSuccessfulVisible = false;

  @ViewChild('radioButtonRSA') rsaElement: ElementRef;
  @ViewChild('radioButtonAES') aesElement: ElementRef;
  @ViewChild('radioButtonBlowfish') blowfishElement: ElementRef;
  @ViewChild('radioButtonTwofish') twofishElement: ElementRef;
  @ViewChild('radioButtonPassword') passwordElement: ElementRef;
  @ViewChild('inputKeySize') keySizeElement: ElementRef;
  @ViewChild('inputAlphaUpper') passwordAlphaUpperElement: ElementRef;
  @ViewChild('inputAlphaLower') passwordAlphaLowerElement: ElementRef;
  @ViewChild('inputNumeric') passwordNumericElement: ElementRef;
  @ViewChild('inputSpecial') passwordSpecialElement: ElementRef;
  @ViewChild('inputKeyName') keyNameElement: ElementRef;
  @ViewChild('buttonSaveKey') saveKeyElement: ElementRef;
  @ViewChild('textareaResult') textareaResultElement: ElementRef;

  ngOnInit() {
    this.getSelectedKeyTypeElement().nativeElement.click();
    this._keySize = this.sanitizeValueForParameter(localStorage.getItem("keygen_key_size"));
    this._passwordAlphaUpper = this.sanitizeValueForParameter(localStorage.getItem("keygen_password_alpha_upper"));
    this._passwordAlphaLower = this.sanitizeValueForParameter(localStorage.getItem("keygen_password_alpha_lower"));
    this._passwordNumeric = this.sanitizeValueForParameter(localStorage.getItem("keygen_password_numeric"));
    this._passwordSpecial = this.sanitizeValueForParameter(localStorage.getItem("keygen_password_special"));
    this.consumeState();
  }

  ngAfterViewInit() {
    if(this.saveKeyElement)
      this.saveKeyElement.nativeElement.click();
  }

  private onCopyToClipboardClick() {
    this.textareaResultElement.nativeElement.select();
    document.execCommand('copy');
    return false;
  }

  onSelectRSA() {
    if(this.selectedKeyType !== KeyType.RSA){
      this.clearResult();
      this.clearKeyGenerationErrors();
      this.selectedKeyType = KeyType.RSA;
      this.updateRadioButtons();
    }
  }

  onSelectAES() {
    if(this.selectedKeyType !== KeyType.AES){
      this.clearResult();
      this.clearKeyGenerationErrors();
      this.selectedKeyType = KeyType.AES;
      this.updateRadioButtons();
    }
  }

  onSelectBlowfish() {
    if(this.selectedKeyType !== KeyType.Blowfish){
      this.clearResult();
      this.clearKeyGenerationErrors();
      this.selectedKeyType = KeyType.Blowfish;
      this.updateRadioButtons();
    }
  }

  onSelectTwofish() {
    if(this.selectedKeyType !== KeyType.Twofish){
      this.clearResult();
      this.clearKeyGenerationErrors();
      this.selectedKeyType = KeyType.Twofish;
      this.updateRadioButtons();
    }
  }

  onSelectPassword() {
    if(this.selectedKeyType !== KeyType.Password){
      this.clearResult();
      this.clearKeyGenerationErrors();
      this.selectedKeyType = KeyType.Password;
      this.updateRadioButtons();
    }
  }

  private onUseKeyClick() {
    this.setupEncryptionState();
    this.router.navigate(["/encryption"]);
    return false;
  }

  private setupEncryptionState() {
    localStorage.setItem("encryption_key_type", this.selectedKeyType.toString());
    localStorage.setItem("encryption_operation", "encrypt");
    localStorage.removeItem("encryption_data");
    if(this.selectedKeyType !== KeyType.RSA){
      localStorage.setItem("encryption_key", this.result);
    }else{
      let keyParts = this.result.split("-----\n-----");
      if(keyParts.length === 2){
        keyParts[0] += "-----";
        keyParts[1] = "-----" + keyParts[1];
        localStorage.removeItem("encryption_key");
        localStorage.setItem("encryption_rsa_private", keyParts[0]);
        localStorage.setItem("encryption_rsa_public", keyParts[1]);
      }else{
        localStorage.setItem("encryption_key", this.result);
      }
    }
  }

  private onPersistKeyClick() {
    this.persistVisible = true;
    return false;
  }

  onSaveKey() {
    if(!this.auth.isLoggedIn()){
      this.saveState();
      this.router.navigate(["/login"]);
    }else{
      this.clearKeyPersistenceErrors();
      this.service.persistKey(this.selectedKeyType, this.keyName, this.result, this.auth.getToken()).then(
        _ => {
          this.persistSuccessfulVisible = true;
          setTimeout(() => {
            this.persistSuccessfulVisible = false;
            this.keyName = "";
            this.clearResult();
          }, 2500);
        },
        error => {
          //console.log(error);
          if(error.status == 401){
            this.auth.logout();
            this.onSaveKey();
          }else if(error.status == 400 || error.status == 500){
            this.errorsPersistence.push(error.statusText);
          }else{
            this.errorsPersistence.push(error.message);
          }
        }
      );
    }
  }

  onGenerateKey() {
    this.clearResult();
    this.clearKeyGenerationErrors();
    this.validateKeyGeneration();
    if(this.errorsGenerator.length == 0){
      if(this.selectedKeyType !== KeyType.Password){
        this.service.generateKey(this.selectedKeyType, Number(this.keySize)).then(
          key => {
            this.result = key as string;
          },
          error => {
            //console.log(error);
            if(error.status == 400){
              this.errorsGenerator.push("Bad request; check key size validity.");
            }else if(error.status == 500){
              this.errorsGenerator.push(error.statusText);
            }else{
              this.errorsGenerator.push(error.message);
            }
          }
        );
      }else{
        this.service.generatePassword(Number(this.passwordAlphaUpper), Number(this.passwordAlphaLower), Number(this.passwordNumeric), Number(this.passwordSpecial)).then(
          password => {
            this.result = password as string;
          },
          error => {
            //console.log(error);
            if(error.status == 400 || error.status == 500){
              this.errorsGenerator.push(error.statusText);
            }else{
              this.errorsGenerator.push(error.message);
            }
          }
        );
      }
    }
  }

  private clearResult() {
    this.result = "";
  }

  private validateKeyGeneration() {
    if(this.selectedKeyType !== KeyType.Password){
      let keySizeString = this.keySize.trim();
      let keySize = Number(keySizeString);
      if(keySizeString.length == 0){
        this.setInputElementInvalidClasses(this.keySizeElement.nativeElement);
        this.errorsGenerator.push("key size can not be empty");
      }else if(keySize === NaN || keySize <= 0){
        this.setInputElementInvalidClasses(this.keySizeElement.nativeElement);
        this.errorsGenerator.push("invalid key size");
      }
    }else{
      let alphaUpperString = this.passwordAlphaUpper.trim();
      let alphaLowerString = this.passwordAlphaLower.trim();
      let numericString = this.passwordNumeric.trim();
      let specialString = this.passwordSpecial.trim();
      let alphaUpper = Number(alphaUpperString);
      let alphaLower = Number(alphaLowerString);
      let numeric = Number(numericString);
      let special = Number(specialString);
      let missing = [];
      let incorrect = [];
      if(alphaUpperString.length == 0){
        this.setInputElementInvalidClasses(this.passwordAlphaUpperElement.nativeElement);
        missing.push("uppercase letters");
      }else if(alphaUpper === NaN || alphaUpper < 0){
        this.setInputElementInvalidClasses(this.passwordAlphaUpperElement.nativeElement);
        incorrect.push("uppercase letters");
      }
      if(alphaLowerString.length == 0){
        this.setInputElementInvalidClasses(this.passwordAlphaLowerElement.nativeElement);
        missing.push("lowercase letters");
      }else if(alphaLower === NaN || alphaLower < 0){
        this.setInputElementInvalidClasses(this.passwordAlphaLowerElement.nativeElement);
        incorrect.push("lowercase letters");
      }
      if(numericString.length == 0){
        this.setInputElementInvalidClasses(this.passwordNumericElement.nativeElement);
        missing.push("numbers");
      }else if(numeric === NaN || numeric < 0){
        this.setInputElementInvalidClasses(this.passwordNumericElement.nativeElement);
        incorrect.push("numbers");
      }
      if(specialString.length == 0){
        this.setInputElementInvalidClasses(this.passwordSpecialElement.nativeElement);
        missing.push("symbols");
      }else if(special === NaN || special < 0){
        this.setInputElementInvalidClasses(this.passwordSpecialElement.nativeElement);
        incorrect.push("symbols");
      }
      if(missing.length != 0){
        this.errorsGenerator.push("the following fields can not be empty: " + missing.join(", "));
      }
      if(incorrect.length != 0){
        this.errorsGenerator.push("the following fields are invalid: " + incorrect.join(", "));
      }
      if(missing.length === 0 && incorrect.length === 0 && alphaUpper === 0 && alphaLower === 0 && numeric === 0 && special === 0){
        this.errorsGenerator.push("will not generate empty password");
      }
    }
  }

  private clearKeyGenerationErrors() {
    this.errorsGenerator = [];
    if(this.keySizeElement) this.removeInputElementInvalidClasses(this.keySizeElement.nativeElement);
    if(this.passwordAlphaUpperElement) this.removeInputElementInvalidClasses(this.passwordAlphaUpperElement.nativeElement);
    if(this.passwordAlphaLowerElement) this.removeInputElementInvalidClasses(this.passwordAlphaLowerElement.nativeElement);
    if(this.passwordNumericElement) this.removeInputElementInvalidClasses(this.passwordNumericElement.nativeElement);
    if(this.passwordSpecialElement) this.removeInputElementInvalidClasses(this.passwordSpecialElement.nativeElement);
  }

  private clearKeyPersistenceErrors() {
    this.errorsPersistence = [];
  }

  private setInputElementInvalidClasses(element: any) {
    this.renderer.addClass(element, "was-validated");
    this.renderer.addClass(element, "is-invalid");
  }

  private removeInputElementInvalidClasses(element: any) {
    this.renderer.removeClass(element, "was-validated");
    this.renderer.removeClass(element, "is-invalid");
  }

  private updateRadioButtons() {
    this.deselectRadioButtons();
    this.selectRadioButton();
  }

  private deselectRadioButtons() {
    this.renderer.removeClass(this.rsaElement.nativeElement, "active");
    this.renderer.addClass(this.rsaElement.nativeElement, "not-active");
    this.renderer.removeClass(this.aesElement.nativeElement, "active");
    this.renderer.addClass(this.aesElement.nativeElement, "not-active");
    this.renderer.removeClass(this.blowfishElement.nativeElement, "active");
    this.renderer.addClass(this.blowfishElement.nativeElement, "not-active");
    this.renderer.removeClass(this.twofishElement.nativeElement, "active");
    this.renderer.addClass(this.twofishElement.nativeElement, "not-active");
    this.renderer.removeClass(this.passwordElement.nativeElement, "active");
    this.renderer.addClass(this.passwordElement.nativeElement, "not-active");
  }

  private selectRadioButton() {
    let element = this.mapKeyTypeToRadioButton(this.selectedKeyType);
    this.renderer.removeClass(element.nativeElement, "not-active");
    this.renderer.addClass(element.nativeElement, "active");

    // remember choice for convenience
    this.persistKeyTypeChoice(this.selectedKeyType);
  }

  private getSelectedKeyTypeElement() : ElementRef {
    let selectedKeyType = localStorage.getItem("keygen_selected_type") as KeyType;
    return this.mapKeyTypeToRadioButton(selectedKeyType);
  }

  private mapKeyTypeToRadioButton(keyType: KeyType) : ElementRef {
    switch(keyType){
      case KeyType.AES:
        return this.aesElement;
      case KeyType.Blowfish:
        return this.blowfishElement;
      case KeyType.Twofish:
        return this.twofishElement;
      case KeyType.Password:
        return this.passwordElement;
      default:
        return this.rsaElement;
    }
  }

  private persistKeyTypeChoice(keyType: KeyType) {
    localStorage.setItem("keygen_selected_type", keyType);
  }

  private sanitizeValueForParameter(value: string) : string {
    if(value)
      return value;
    else
      return "0";
  }

  private saveState() {
    sessionStorage.setItem("keygen_result", this.result);
    sessionStorage.setItem("keygen_persist_visible", this.persistVisible ? "true" : "");
    sessionStorage.setItem("keygen_save_key_name", this.keyName);
    sessionStorage.setItem("login_redirect_to", "key-generation");
  }

  private consumeState() {
    if(sessionStorage.getItem("keygen_result"))
      this.result = sessionStorage.getItem("keygen_result");
    if(sessionStorage.getItem("keygen_persist_visible"))
      this.persistVisible = true;
    if(sessionStorage.getItem("keygen_save_key_name"))
      this.keyName = sessionStorage.getItem("keygen_save_key_name");

    sessionStorage.removeItem("keygen_result");
    sessionStorage.removeItem("keygen_persist_visible");
    sessionStorage.removeItem("keygen_save_key_name");
  }
}
