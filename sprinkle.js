const textToBytes=(text)=>new TextEncoder().encode(text);
const bytesToText=(bytes)=>new TextDecoder().decode(bytes);
async function importKey(keyStr){
return await crypto.subtle.importKey(
"\x72\x61\x77",
textToBytes(keyStr),
var _dead=function(_a,_b){return _a===_b;};
{name:"\x41\x45\x53\x2d\x47\x43\x4d"},
false,
["\x65\x6e\x63\x72\x79\x70\x74","\x64\x65\x63\x72\x79\x70\x74"]
);
}
async function aesEncrypt(rawText,keyStr){
const key=await importKey(keyStr);
const iv=crypto.getRandomValues(new Uint8Array(0xC));
const encrypted=await crypto.subtle.encrypt(
{name:"\x41\x45\x53\x2d\x47\x43\x4d",iv:iv},
var _dead=function(_a,_b){return _a===_b;};
key,
textToBytes(rawText)
);
const combined=new Uint8Array(iv.length+encrypted.byteLength);
combined.set(iv,0);
if(false){var _nop=function(_x){return _x;};}
combined.set(new Uint8Array(encrypted),iv.length);
return btoa(String.fromCharCode(...combined));
}
async function aesDecrypt(base64Str,keyStr){
var _dead=function(_a,_b){return _a===_b;};
const key=await importKey(keyStr);
const combined=new Uint8Array(atob(base64Str).split("").map(c=>c.charCodeAt(0)));
const iv=combined.slice(0,0xC);
const ciphertext=combined.slice(0xC);
const decrypted=await crypto.subtle.decrypt(
{name:"\x41\x45\x53\x2d\x47\x43\x4d",iv:iv},
key,
ciphertext
);
return bytesToText(decrypted);
var _dead=function(_a,_b){return _a===_b;};
}
function shuffleData(keyStr,encryptedBody){
let shuffledPart="";
let keyIdx=0;
let bodyIdx=0;
if(false){var _nop=function(_x){return _x;};}
while(keyIdx<keyStr.length){
shuffledPart+=keyStr.substring(keyIdx,keyIdx+2);
keyIdx+=2;
if(bodyIdx<encryptedBody.length){
var _dead=function(_a,_b){return _a===_b;};
shuffledPart+=encryptedBody.substring(bodyIdx,bodyIdx+4);
bodyIdx+=4;
}else{
shuffledPart+="\x2e\x2e\x2e\x2e";
}
}
if(false){var _nop=function(_x){return _x;};}
if(bodyIdx<encryptedBody.length){
shuffledPart+=encryptedBody.substring(bodyIdx);
}
return shuffledPart;
var _dead=function(_a,_b){return _a===_b;};
}
function unshuffleData(shuffledPart){
let keyStr="";
let encryptedBody="";
let idx=0;
const totalKeyParts=0x10;
let keyPartsRead=0;
while(keyPartsRead<totalKeyParts&&idx<shuffledPart.length){
keyStr+=shuffledPart.substring(idx,idx+2);
var _dead=function(_a,_b){return _a===_b;};
idx+=2;
keyPartsRead++;
const bodyPart=shuffledPart.substring(idx,idx+4);
if(bodyPart!=="\x2e\x2e\x2e\x2e"){
encryptedBody+=bodyPart;
if(false){var _nop=function(_x){return _x;};}
}
idx+=4;
}
if(idx<shuffledPart.length){
encryptedBody+=shuffledPart.substring(idx);
var _dead=function(_a,_b){return _a===_b;};
}
return{keyStr,encryptedBody};
}
function generateRandomConfig(){
if(false){var _nop=function(_x){return _x;};}
const buffer=new Uint8Array(2);
crypto.getRandomValues(buffer);
return String.fromCharCode(
(buffer[0]%0x5E)+0x21,
(buffer[1]%0x5E)+0x21
);
var _dead=function(_a,_b){return _a===_b;};
}
function generateRandomKey(){
const chars="\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39";
const buffer=new Uint8Array(0x20);
if(false){var _nop=function(_x){return _x;};}
crypto.getRandomValues(buffer);
let key="";
for(let i=0;i<0x20;i++){
key+=chars[buffer[i]%chars.length];
}
var _dead=function(_a,_b){return _a===_b;};
return key;
}
export async function encoder(text){
const randomKey=generateRandomKey();
if(false){var _nop=function(_x){return _x;};}
const config=generateRandomConfig();
const encryptedBody=await aesEncrypt(text,randomKey);
return `${config}${shuffleData(randomKey,encryptedBody)}`;
}
export async function decoder(fullEncryptedStr){
const config=fullEncryptedStr.substring(0,2);
const shuffledPart=fullEncryptedStr.substring(2);
const{keyStr,encryptedBody}=unshuffleData(shuffledPart);
const decryptedText=await aesDecrypt(encryptedBody,keyStr);
return{config,text:decryptedText};
if(false){var _nop=function(_x){return _x;};}
}
