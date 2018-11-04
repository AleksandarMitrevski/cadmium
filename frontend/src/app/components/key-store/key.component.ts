import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { Key } from '../../models/key';
import { KeyType } from 'src/app/models/key-type';

enum ComponentMode {
  Normal,
  Rename
};

@Component({
  selector: 'app-key',
  templateUrl: './key.component.html',
  styleUrls: ['./key.component.css']
})
export class KeyComponent implements OnInit {

  constructor() { }

  @Input() key: Key;
  @Output() onUse: EventEmitter<{}> = new EventEmitter();
  @Output() onRename: EventEmitter<string> = new EventEmitter();
  @Output() onDelete: EventEmitter<{}> = new EventEmitter();

  componentModes = ComponentMode;
  private keyTypes = KeyType;
  mode = ComponentMode.Normal;

  private renameValue: string = "";

  ngOnInit() {
  }

  private formatDate(date: Date) {
    let formatOptions = { year: 'numeric', month: 'numeric', day: 'numeric' };
    return date.toLocaleDateString(undefined, formatOptions);
  }

  private onUseClick() {
    this.onUse.emit();
    return false;
  }

  private onRenameClick() {
    this.mode = ComponentMode.Rename;
    this.renameValue = this.key.name;
    return false;
  }

  private onSubmitRenameClick() {
    if(this.renameValue != this.key.name)
      this.onRename.emit(this.renameValue);
    this.mode = ComponentMode.Normal;
  }

  private onCancelRenameClick() {
    this.mode = ComponentMode.Normal;
  }

  private onDeleteClick() {
    this.onDelete.emit();
    return false;
  }

}
