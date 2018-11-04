CREATE OR REPLACE DATABASE cadmium;
USE cadmium;

CREATE TABLE users (
	id INT AUTO_INCREMENT NOT NULL,
	username VARCHAR(100) UNIQUE NOT NULL,
	password_hash CHAR(64) NOT NULL,
	salt CHAR(32) NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE key_types (
	id INT AUTO_INCREMENT NOT NULL,
	key_type_name VARCHAR(10) NOT NULL,
	PRIMARY KEY (id)
);

CREATE TABLE user_keys (
	id INT AUTO_INCREMENT NOT NULL,
	key_name VARCHAR(100) NOT NULL,
	key_type INT NOT NULL,
	key_value TEXT NOT NULL,
	user_id INT NOT NULL,
	created_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
	FOREIGN KEY (key_type) REFERENCES key_types(id),
	FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO key_types (key_type_name) VALUES ('RSA');
INSERT INTO key_types (key_type_name) VALUES ('AES');
INSERT INTO key_types (key_type_name) VALUES ('Blowfish');
INSERT INTO key_types (key_type_name) VALUES ('Twofish');
INSERT INTO key_types (key_type_name) VALUES ('Password');

/* sample user: Test / Test */
INSERT INTO users (username, password_hash, salt) VALUES ('Test', 'eb1b7f79e2d2a815f9a29048aa34c7beaf05425045569e83a8b8011f8bbd735b', '2jK@7mKeMQzY:4v?WTg-50r6M+chHnHl');

/* sample keys for user: RSA - 2048-bit, AES - 256-bit, random password - 5, 5, 5, 5*/
INSERT INTO user_keys (key_name, key_type, key_value, user_id) VALUES ('Sample RSA key', 1, CONCAT('-----BEGIN RSA PRIVATE KEY-----', CHAR(10), 'MIIEowIBAAKCAQEAu6gPXMJoBo8CLGcAzUyf62imUpxDEh1upwoHDM7M3cs+Qk9g', CHAR(10), 'SjuEal01uidcYShMm7PNAQ0FzzWB9saAA76nqUF2JQLd90g3VlRkMCzwygTzIUm8', CHAR(10), 'fAaQxtG8MNIie1k23BqDtqUTDQl/8KuOuJm0dLKoDVBa8V7YEIBdQJ/vGTzRrHjT', CHAR(10), '+r/y+Pe8Ppe8FCw18oj9SoFpCBzlxqfOCqkE28sruGOnTctLEVEcEW79+tjVZHc8', CHAR(10), 'Zwj4Be0FLTSkVIu6wrq1psJnitLPV9k1+kg5/iikWvPSfBLRVeBTqVPrjf9PJ6mu', CHAR(10), 'Tsr/KGAzcbrZ6Kk7dkrsp9ldRAKnUOwlEVp6twIDAQABAoIBAHfU+App8nfNtruY', CHAR(10), 'AwEWn0B6kUtLkeDtfo2Yb6wUGuq/MMCzY2/D1ej+IKMBI5K/YzxCcvTq1fzd1GI7', CHAR(10), 'm9/ITdRdgw5baFbSfNPaDChfalv3ETL+nSguISF1KVGbvn06GTgwjk+B1kqK+HI9', CHAR(10), 'e2QScxPaSkpGN+zOffb7oZD1EH/yJ+CuVW6yorFnhn06kWnvlaZ1VyzXCbg/FmoU', CHAR(10), 'plykDXMUyapBlWFPDSnzccSCWSM64ShhlDRUl7823QwSO1LsggFxyFsCjbdD/xni', CHAR(10), '2js5LvSsehoxkZYNFtbwBCmxBWK+MzukYYi61a63rLn0YP3BDmRk7uiUlnWDpPxZ', CHAR(10), 'w6Lt3wECgYEAy9yZI7E5bEhQ0AWiog9X+c7B6ySNY8NuTGwVsDIG42Anh7xo0g1D', CHAR(10), 'XHMuiPoB406cA8vkgW4Y5pdYfCF/mwFHMRTjLO2wFO86A7HaZwuohuG6h+uvsUQg', CHAR(10), 'JnzNgMduX0RNyowZuNFQ6JLQrBltREQqdxkEJO+fDgBaiFxvBEgxmPcCgYEA66Z1', CHAR(10), 'ty5UGcG6x4oytX/1uO2S/gWd8yRBrJdLb+SVZPvzIjXHVFKr7zLmGlDp8Z4VIPOK', CHAR(10), 'vOTLol8QRScRMzuCjzJsx6mzLFDicWXNjYcdNXqvhb4E/ZUuLmCZMnhCdb3iRXSy', CHAR(10), 'XdD8LxFJ629YcVSqvFq2IKo/SFbQlqd4WDbtfEECgYEAoXeEQ+TnGoDcoScVfU6x', CHAR(10), '28aLiXdWFaKBBj7FntzA3+8U4Em2rEidBeik/xEl1ag5ojgoMOvHBTzydL8Dlv4Y', CHAR(10), 'KSPmG3vXb31bcfm4hs2RGeRIHcfrTHgtDs7i5hEPtp0fEEKPTPddIhjG9sjc5qkn', CHAR(10), 'CVXjFm5EiI53JnIv7DBSOFkCgYArep8lmUqzJeeMgZcxndZ8tHj2nZqzDfGAIros', CHAR(10), 'fwSBiWsm2L1adZZ7n+yM1nkTt5M2bTkf+ScJYnjiCX9G8Kf6O9eOT2Vbu+DMA3iV', CHAR(10), 'sGRXRbe0+YZ6M1g9/lzFzyKUDuD857cxUCn3lT0KT5UF9BU8g5AvHrpmYn5CDcxK', CHAR(10), 'mnffAQKBgEHWrZwy9Sf01CVfVQfSpq8QEDJqLYjXfP1xKqOS/lDD3bJGn94A9Y6T', CHAR(10), 'JRRoCB/cIIi0Wb3PRtu/a86HFm81uy3+7a4RVI4w4CTZH8zlHterdJECMy6YazQf', CHAR(10), '8kUsrNOlMKOJ7ub6A+GL8ACizRg/w11r3+3cmEYYCNkR6fhQNRBZ', CHAR(10), '-----END RSA PRIVATE KEY-----', CHAR(10), '-----BEGIN PUBLIC KEY-----', CHAR(10), 'MIIBCgKCAQEAu6gPXMJoBo8CLGcAzUyf62imUpxDEh1upwoHDM7M3cs+Qk9gSjuE', CHAR(10), 'al01uidcYShMm7PNAQ0FzzWB9saAA76nqUF2JQLd90g3VlRkMCzwygTzIUm8fAaQ', CHAR(10), 'xtG8MNIie1k23BqDtqUTDQl/8KuOuJm0dLKoDVBa8V7YEIBdQJ/vGTzRrHjT+r/y', CHAR(10), '+Pe8Ppe8FCw18oj9SoFpCBzlxqfOCqkE28sruGOnTctLEVEcEW79+tjVZHc8Zwj4', CHAR(10), 'Be0FLTSkVIu6wrq1psJnitLPV9k1+kg5/iikWvPSfBLRVeBTqVPrjf9PJ6muTsr/', CHAR(10), 'KGAzcbrZ6Kk7dkrsp9ldRAKnUOwlEVp6twIDAQAB', CHAR(10), '-----END PUBLIC KEY-----'), 1);
INSERT INTO user_keys (key_name, key_type, key_value, user_id) VALUES ('Sample AES key', 2, '52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649', 1);
INSERT INTO user_keys (key_name, key_type, key_value, user_id) VALUES ('Sample Password key', 5, ';l<%%Iv9C8b1B4AzG2(x', 1);
/* CHAR(10) */ 