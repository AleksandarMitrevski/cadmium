import { Component, OnInit, ViewChild, ElementRef, Renderer2 } from '@angular/core';
import { EncryptionService } from './encryption.service';
import { KeyType } from '../../models/key-type';

enum Operation {
  Encrypt = "encrypt",
  Decrypt = "decrypt"
}

@Component({
  selector: 'app-encryption',
  templateUrl: './encryption.component.html',
  styleUrls: ['./encryption.component.css']
})
export class EncryptionComponent implements OnInit {

  constructor(private renderer: Renderer2, private service: EncryptionService) { }

  private selectedKeyType: KeyType = KeyType.RSA;
  private selectedOperation: Operation = Operation.Encrypt;
  private rsaKeyParts: Array<string> = null;

  private _key: string = "";
  get key(): string {
    return this._key;
  }
  set key(key: string) {
    this._key = key;
    localStorage.setItem("encryption_key", key);
  }
  private _data: string = "";
  get data(): string {
    return this._data;
  }
  set data(data: string) {
    this._data = data;
    localStorage.setItem("encryption_data", data);
  }
  result: string = "";
  errors: Array<string> = [];

  @ViewChild('radioButtonRSA') rsaElement: ElementRef;
  @ViewChild('radioButtonAES') aesElement: ElementRef;
  @ViewChild('radioButtonBlowfish') blowfishElement: ElementRef;
  @ViewChild('radioButtonTwofish') twofishElement: ElementRef;
  @ViewChild('radioButtonEncrypt') encryptElement: ElementRef;
  @ViewChild('radioButtonDecrypt') decryptElement: ElementRef;
  @ViewChild('textareaData') textareaDataElement: ElementRef;
  @ViewChild('textareaKey') textareaKeyElement: ElementRef;
  @ViewChild('textareaResult') textareaResultElement: ElementRef;

  ngOnInit() {
    this.getSelectedKeyTypeElement().nativeElement.click();
    this.getSelectedOperationElement().nativeElement.click();
    if(this.selectedKeyType === KeyType.RSA && localStorage.getItem("encryption_rsa_private") && localStorage.getItem("encryption_rsa_public")){
      let keyParts = [];
      keyParts.push(localStorage.getItem("encryption_rsa_private"));
      keyParts.push(localStorage.getItem("encryption_rsa_public"));
      this.rsaKeyParts = keyParts;
      this.updateRSAKey();
    }else if(localStorage.getItem("encryption_key")){
      this.key = this.sanitizeValueForParameter(localStorage.getItem("encryption_key"));
    }
    this.data = this.sanitizeValueForParameter(localStorage.getItem("encryption_data"));
  }

  onSelectRSA() {
    if(this.selectedKeyType !== KeyType.RSA){
      this.clearResult();
      this.clearErrors();
      this.selectedKeyType = KeyType.RSA;
      this.updateKeyRadioButtons();
    }
  }

  onSelectAES() {
    if(this.selectedKeyType === KeyType.RSA)
      this.decoupleRSAKey();
    if(this.selectedKeyType !== KeyType.AES){
      this.clearResult();
      this.clearErrors();
      this.selectedKeyType = KeyType.AES;
      this.updateKeyRadioButtons();
    }
  }

  onSelectBlowfish() {
    if(this.selectedKeyType === KeyType.RSA)
      this.decoupleRSAKey();
    if(this.selectedKeyType !== KeyType.Blowfish){
      this.clearResult();
      this.clearErrors();
      this.selectedKeyType = KeyType.Blowfish;
      this.updateKeyRadioButtons();
    }
  }

  onSelectTwofish() {
    if(this.selectedKeyType === KeyType.RSA)
      this.decoupleRSAKey();
    if(this.selectedKeyType !== KeyType.Twofish){
      this.clearResult();
      this.clearErrors();
      this.selectedKeyType = KeyType.Twofish;
      this.updateKeyRadioButtons();
    }
  }

  onSelectEncrypt() {
    if(this.selectedOperation !== Operation.Encrypt){
      this.clearResult();
      this.clearErrors();
      this.selectedOperation = Operation.Encrypt;
      this.updateOperationRadioButtons();
      this.updateRSAKey();
    }
  }

  onSelectDecrypt() {
    if(this.selectedOperation !== Operation.Decrypt){
      this.clearResult();
      this.clearErrors();
      this.selectedOperation = Operation.Decrypt;
      this.updateOperationRadioButtons();
      this.updateRSAKey();
    }
  }

  onKeyChange() {
    this.decoupleRSAKey(false);
  }

  private onCopyToClipboardClick() {
    this.textareaResultElement.nativeElement.select();
    document.execCommand('copy');
    return false;
  }

  onExecute() {
    this.clearResult();
    this.clearErrors();
    this.validate();
    if(this.errors.length == 0){
      let operation = this.mapOperationToServiceFunction(this.selectedOperation);
      operation(this.selectedKeyType, this.key, this.data).then(
        result => {
          this.result = result as string;
        },
        error => {
          //console.log(error);
          if(error.status == 400){
            this.errors.push("Bad request; check key validity.\nHint: use the key generator 'use' link to check proper key format if unsure.");
          }else if(error.status == 500){
            this.errors.push(error.statusText);
          }else{
            this.errors.push(error.message);
          }
        }
      );
    }
  }

  private validate() {
    if(this.data.length == 0){
      this.setInputElementInvalidClasses(this.textareaDataElement.nativeElement);
      this.errors.push("data can not be empty");
    }
    if(this.key.length == 0){
      this.setInputElementInvalidClasses(this.textareaKeyElement.nativeElement);
      this.errors.push("key can not be empty");
    }
  }

  private clearResult() {
    this.result = "";
  }

  private clearErrors() {
    this.errors = [];
    if(this.textareaKeyElement) this.removeInputElementInvalidClasses(this.textareaKeyElement.nativeElement);
    if(this.textareaDataElement) this.removeInputElementInvalidClasses(this.textareaDataElement.nativeElement);
  }

  private setInputElementInvalidClasses(element: any) {
    this.renderer.addClass(element, "was-validated");
    this.renderer.addClass(element, "is-invalid");
  }

  private removeInputElementInvalidClasses(element: any) {
    this.renderer.removeClass(element, "was-validated");
    this.renderer.removeClass(element, "is-invalid");
  }

  private updateKeyRadioButtons() {
    this.deselectKeyRadioButtons();
    this.selectKeyRadioButton();
  }

  private deselectKeyRadioButtons() {
    this.renderer.removeClass(this.rsaElement.nativeElement, "active");
    this.renderer.addClass(this.rsaElement.nativeElement, "not-active");
    this.renderer.removeClass(this.aesElement.nativeElement, "active");
    this.renderer.addClass(this.aesElement.nativeElement, "not-active");
    this.renderer.removeClass(this.blowfishElement.nativeElement, "active");
    this.renderer.addClass(this.blowfishElement.nativeElement, "not-active");
    this.renderer.removeClass(this.twofishElement.nativeElement, "active");
    this.renderer.addClass(this.twofishElement.nativeElement, "not-active");
  }

  private selectKeyRadioButton() {
    let element = this.mapKeyTypeToRadioButton(this.selectedKeyType);
    this.renderer.removeClass(element.nativeElement, "not-active");
    this.renderer.addClass(element.nativeElement, "active");

    // remember choice for convenience
    this.persistKeyTypeChoice(this.selectedKeyType);
  }

  private updateOperationRadioButtons() {
    this.deselectOperationRadioButtons();
    this.selectOperationRadioButton();
  }

  private deselectOperationRadioButtons() {
    this.renderer.removeClass(this.encryptElement.nativeElement, "active");
    this.renderer.addClass(this.encryptElement.nativeElement, "not-active");
    this.renderer.removeClass(this.decryptElement.nativeElement, "active");
    this.renderer.addClass(this.decryptElement.nativeElement, "not-active");
  }

  private selectOperationRadioButton() {
    let element = this.mapOperationToRadioButton(this.selectedOperation);
    this.renderer.removeClass(element.nativeElement, "not-active");
    this.renderer.addClass(element.nativeElement, "active");

    // remember choice for convenience
    this.persistOperationChoice(this.selectedOperation);
  }

  private getSelectedKeyTypeElement() : ElementRef {
    let selectedKeyType = localStorage.getItem("encryption_key_type") as KeyType;
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
      default:
        return this.rsaElement;
    }
  }

  private getSelectedOperationElement() : ElementRef {
    let selectedOperation = localStorage.getItem("encryption_operation") as Operation;
    return this.mapOperationToRadioButton(selectedOperation);
  }

  private mapOperationToRadioButton(operation: Operation) : ElementRef {
    switch(operation){
      case Operation.Decrypt:
        return this.decryptElement;
      default:
        return this.encryptElement;
    }
  }

  private mapOperationToServiceFunction(operation: Operation) {
    switch(operation){
      case Operation.Decrypt:
        return this.service.decrypt.bind(this.service);
      default:
        return this.service.encrypt.bind(this.service);
    }
  }

  private persistKeyTypeChoice(keyType: KeyType) {
    localStorage.setItem("encryption_key_type", keyType);
  }

  private persistOperationChoice(operation: Operation) {
    localStorage.setItem("encryption_operation", operation);
  }

  private decoupleRSAKey(updateKey: boolean = true) {
    if(this.rsaKeyParts){
      if(updateKey) this.key = this.rsaKeyParts.join("\n");
      this.rsaKeyParts = null;
      localStorage.removeItem("encryption_rsa_private");
      localStorage.removeItem("encryption_rsa_public");
    }
  }

  private updateRSAKey() {
    if(this.rsaKeyParts){
      if(this.selectedOperation === Operation.Decrypt){
        this.key = this.rsaKeyParts[0];
      }else{
        this.key = this.rsaKeyParts[1];
      }
    }
  }

  private sanitizeValueForParameter(value: string) : string {
    if(value)
      return value;
    else
      return "";
  }
}
