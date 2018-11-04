import { Component, OnInit, ViewChild, ElementRef, Renderer2 } from '@angular/core';
import { HashingService } from './hashing.service';
import { HashType } from '../../models/hash-type';

@Component({
  selector: 'app-hashing',
  templateUrl: './hashing.component.html',
  styleUrls: ['./hashing.component.css']
})
export class HashingComponent implements OnInit {

  constructor(private renderer: Renderer2, private service: HashingService) { }

  data: string = "";
  result: string = "";
  errors: Array<string> = [];
  private selectedHashType: HashType = HashType.SHA224;

  @ViewChild('radioButtonSHA224') sha224Element: ElementRef;
  @ViewChild('radioButtonSHA256') sha256Element: ElementRef;
  @ViewChild('radioButtonSHA512') sha512Element: ElementRef;
  @ViewChild('radioButtonMD5') md5Element: ElementRef;
  @ViewChild('textareaResult') textareaResultElement: ElementRef;

  ngOnInit() {
    this.getSelectedHashingFunctionElement().nativeElement.click();
  }

  onSelectSHA224() {
    if(this.selectedHashType !== HashType.SHA224){
      this.clearResultAndErrors();
      this.selectedHashType = HashType.SHA224;
      this.updateRadioButtons();
    }
  }

  onSelectSHA256() {
    if(this.selectedHashType !== HashType.SHA256){
      this.clearResultAndErrors();
      this.selectedHashType = HashType.SHA256;
      this.updateRadioButtons();
    }
  }

  onSelectSHA512() {
    if(this.selectedHashType !== HashType.SHA512){
      this.clearResultAndErrors();
      this.selectedHashType = HashType.SHA512;
      this.updateRadioButtons();
    }
  }

  onSelectMD5() {
    if(this.selectedHashType !== HashType.MD5){
      this.clearResultAndErrors();
      this.selectedHashType = HashType.MD5;
      this.updateRadioButtons();
    }
  }

  onCalculateHash() {
    this.clearResultAndErrors();
    this.service.calculateHash(this.data, this.selectedHashType).then(
      hash => {
        this.result = hash as string;
      },
      error => {
        //console.log(error);
        if(error.status == 500){
          this.errors.push(error.statusText);
        }else{
          this.errors.push(error.message);
        }
      }
    );
  }

  private clearResultAndErrors() {
    this.result = "";
    this.errors = [];
  }

  private clearErrors() {
    this.errors = [];
  }

  onCopyToClipboardClick() {
    this.textareaResultElement.nativeElement.select();
    document.execCommand('copy');
    return false;
  }

  private updateRadioButtons() {
    this.deselectRadioButtons();
    this.selectRadioButton();
  }

  private deselectRadioButtons() {
    this.renderer.removeClass(this.sha224Element.nativeElement, "active");
    this.renderer.addClass(this.sha224Element.nativeElement, "not-active");
    this.renderer.removeClass(this.sha256Element.nativeElement, "active");
    this.renderer.addClass(this.sha256Element.nativeElement, "not-active");
    this.renderer.removeClass(this.sha512Element.nativeElement, "active");
    this.renderer.addClass(this.sha512Element.nativeElement, "not-active");
    this.renderer.removeClass(this.md5Element.nativeElement, "active");
    this.renderer.addClass(this.md5Element.nativeElement, "not-active");
  }

  private selectRadioButton() {
    let element = this.mapHashTypeToRadioButton(this.selectedHashType);
    this.renderer.removeClass(element.nativeElement, "not-active");
    this.renderer.addClass(element.nativeElement, "active");

    // remember choice for convenience
    this.persistHashingFunctionChoice(this.selectedHashType);
  }

  private getSelectedHashingFunctionElement() : ElementRef {
    let selectedHashingFunction = localStorage.getItem("hashing_selected_function") as HashType;
    return this.mapHashTypeToRadioButton(selectedHashingFunction);
  }

  private mapHashTypeToRadioButton(hashType: HashType) : ElementRef {
    switch(hashType){
      case HashType.SHA256:
        return this.sha256Element;
      case HashType.SHA512:
        return this.sha512Element;
      case HashType.MD5:
        return this.md5Element;
      default:
        return this.sha224Element;
    }
  }

  private persistHashingFunctionChoice(hashType: HashType) {
    localStorage.setItem("hashing_selected_function", hashType);
  }
}

