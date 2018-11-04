import { KeyType } from '../models/key-type';

export class Key {
    constructor(
        public id: number,
        public name: string,
        public type: KeyType,
        public value: string,
        public createdOn: Date
    ) { }
}