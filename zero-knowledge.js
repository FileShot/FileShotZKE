// Zero-Knowledge Encryption Utilities
// KDF: Argon2id (new files) | PBKDF2-SHA256 fallback (legacy files)
// Format v2: [0x02][salt32][iv12][ciphertext]
// Format v1 (legacy): [salt16][iv12][ciphertext]  (no version byte)

const ZK_ALGORITHM = 'AES-GCM';
const ZK_KEY_LENGTH = 256;
const IV_LENGTH = 12;
const SALT_LENGTH = 32;
const LEGACY_SALT_LENGTH = 16;
const FORMAT_VERSION = 0x02;

// Argon2id parameters (OWASP recommended, browser-friendly)
const ARGON2_MEMORY = 65536;   // 64 MB
const ARGON2_ITERATIONS = 2;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LEN = 32;

const _textEncoder = new TextEncoder();

const _concatU8 = (parts) => {
  const total = parts.reduce((s, p) => s + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.byteLength; }
  return out;
};

// ─── Blake2b (used by Argon2id) ───────────────────────────────────────────────
const _B2IV = new Float64Array([
  0xf3bcc908,0x6a09e667,0x84caa73b,0xbb67ae85,
  0xfe94f82b,0x3c6ef372,0x5f1d36f1,0xa54ff53a,
  0xade682d1,0x510e527f,0x2b3e6c1f,0x9b05688c,
  0xfb41bd6b,0x1f83d9ab,0x137e2179,0x5be0cd19
]);
const _SIGMA = [
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
  [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
  [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
  [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
  [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
];

function _b2b(out, outlen, key, keylen, input, inlen) {
  const h=new Uint32Array(16),m=new Uint32Array(32),v=new Uint32Array(32),c=new Uint32Array(2),blk=new Uint8Array(128);
  let pos=0;
  for(let i=0;i<16;i++){h[i*2]=(_B2IV[i]&0xFFFFFFFF)>>>0;h[i*2+1]=Math.floor(_B2IV[i]/0x100000000)>>>0;}
  h[0]^=0x01010000^(keylen<<8)^outlen;
  if(keylen>0){blk.set(key.subarray(0,keylen));pos=128;}
  function G(r,i,a,b,cc,d){
    const x0=2*_SIGMA[r][2*i],x1=x0+1,y0=2*_SIGMA[r][2*i+1],y1=y0+1;
    let Aa=v[2*a],Ab=v[2*a+1],Ba=v[2*b],Bb=v[2*b+1],Ca=v[2*cc],Cb=v[2*cc+1],Da=v[2*d],Db=v[2*d+1];
    let xa=m[x0],xb=m[x1],ya=m[y0],yb=m[y1],w,wc,wh,t,t2;
    w=(Aa+Ba+xa)>>>0;wc=(w<Aa||(w===Aa&&Ba+xa<Ba))?1:0;wh=(Ab+Bb+xb+wc)>>>0;Aa=w;Ab=wh;
    t=Da^Aa;Da=Db^Ab;Db=t;
    w=(Ca+Da)>>>0;wc=(w<Ca)?1:0;wh=(Cb+Db+wc)>>>0;Ca=w;Cb=wh;
    t=(Ba^Ca);t2=(Bb^Cb);Ba=((t>>>24)|(t2<<8))>>>0;Bb=((t2>>>24)|(t<<8))>>>0;
    w=(Aa+Ba+ya)>>>0;wc=(w<Aa||(w===Aa&&Ba+ya<Ba))?1:0;wh=(Ab+Bb+yb+wc)>>>0;Aa=w;Ab=wh;
    t=Da^Aa;t2=Db^Ab;Da=((t>>>16)|(t2<<16))>>>0;Db=((t2>>>16)|(t<<16))>>>0;
    w=(Ca+Da)>>>0;wc=(w<Ca)?1:0;wh=(Cb+Db+wc)>>>0;Ca=w;Cb=wh;
    t=Ba^Ca;t2=Bb^Cb;Ba=((t2>>>31)|(t<<1))>>>0;Bb=((t>>>31)|(t2<<1))>>>0;
    v[2*a]=Aa;v[2*a+1]=Ab;v[2*b]=Ba;v[2*b+1]=Bb;v[2*cc]=Ca;v[2*cc+1]=Cb;v[2*d]=Da;v[2*d+1]=Db;
  }
  function compress(last){
    for(let i=0;i<16;i++)v[i]=h[i];
    for(let i=0;i<8;i++){v[16+i*2]=(_B2IV[i]&0xFFFFFFFF)>>>0;v[16+i*2+1]=Math.floor(_B2IV[i]/0x100000000)>>>0;}
    v[24]^=c[0];v[26]^=c[1];
    if(last){v[28]=~v[28]>>>0;v[29]=~v[29]>>>0;}
    const dv=new DataView(blk.buffer);
    for(let i=0;i<32;i++)m[i]=dv.getUint32(i*4,true);
    for(let r=0;r<12;r++){G(r,0,0,4,8,12);G(r,1,1,5,9,13);G(r,2,2,6,10,14);G(r,3,3,7,11,15);G(r,4,0,5,10,15);G(r,5,1,6,11,12);G(r,6,2,7,8,13);G(r,7,3,4,9,14);}
    for(let i=0;i<16;i++)h[i]^=v[i]^v[16+i];
  }
  function update(inp){for(let i=0;i<inp.length;i++){if(pos===128){c[0]=(c[0]+128)>>>0;if(c[0]<128)c[1]=(c[1]+1)>>>0;compress(false);pos=0;}blk[pos++]=inp[i];}}
  if(inlen>0)update(input.subarray(0,inlen));
  c[0]=(c[0]+pos)>>>0;if(c[0]<pos)c[1]=(c[1]+1)>>>0;
  while(pos<128)blk[pos++]=0;compress(true);
  out.set(new Uint8Array(h.buffer).slice(0,outlen));
}

function _Hprime(outLen, input) {
  const le32=(n)=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;};
  if(outLen<=64){const buf=_concatU8([le32(outLen),input]);const h=new Uint8Array(outLen);_b2b(h,outLen,new Uint8Array(0),0,buf,buf.length);return h;}
  const r=Math.ceil(outLen/32)-2;
  const buf0=_concatU8([le32(outLen),input]);const A=[];
  let prev=new Uint8Array(64);_b2b(prev,64,new Uint8Array(0),0,buf0,buf0.length);A.push(prev.slice(0,32));
  for(let i=1;i<r;i++){const nx=new Uint8Array(64);_b2b(nx,64,new Uint8Array(0),0,prev,prev.length);A.push(nx.slice(0,32));prev=nx;}
  const ll=outLen-32*r;const last=new Uint8Array(ll);_b2b(last,ll,new Uint8Array(0),0,prev,prev.length);A.push(last);
  return _concatU8(A);
}

// ─── Argon2id ─────────────────────────────────────────────────────────────────
function argon2id(password, salt, memory=ARGON2_MEMORY, iterations=ARGON2_ITERATIONS, parallelism=ARGON2_PARALLELISM, hashLen=ARGON2_HASH_LEN) {
  const le32=(n)=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,true);return b;};
  const p=parallelism,m=Math.max(4*p,memory),q=Math.floor(m/p),seg=Math.floor(q/4);
  const h0in=_concatU8([le32(p),le32(hashLen),le32(m),le32(iterations),le32(0x13),le32(19),le32(password.length),password,le32(salt.length),salt,le32(0),le32(0)]);
  const H0=new Uint8Array(64);_b2b(H0,64,new Uint8Array(0),0,h0in,h0in.length);
  const B=new Array(m);for(let i=0;i<m;i++)B[i]=new Uint32Array(256);
  for(let lane=0;lane<p;lane++){
    const b0i=_concatU8([H0,le32(0),le32(lane)]);const b0=_Hprime(1024,b0i);B[lane*q].set(new Uint32Array(b0.buffer,0,256));
    const b1i=_concatU8([H0,le32(1),le32(lane)]);const b1=_Hprime(1024,b1i);B[lane*q+1].set(new Uint32Array(b1.buffer,0,256));
  }
  function GB(v,a,b,c,d){
    function a64(al,ah,bl,bh){const lo=(al+bl)>>>0;return[lo,(ah+bh+(lo<al?1:0))>>>0];}
    function m64l(al,bl){return Math.imul(al,bl)>>>0;}
    function x64(al,ah,bl,bh){return[(al^bl)>>>0,(ah^bh)>>>0];}
    function r32(l,h){return[h,l];}function r24(l,h){return[((l>>>24)|(h<<8))>>>0,((h>>>24)|(l<<8))>>>0];}
    function r16(l,h){return[((l>>>16)|(h<<16))>>>0,((h>>>16)|(l<<16))>>>0];}function r63(l,h){return[((l>>>63)|(h<<1))>>>0,((h>>>63)|(l<<1))>>>0];}
    let[al,ah]=[v[2*a],v[2*a+1]],[bl,bh]=[v[2*b],v[2*b+1]],[cl,ch]=[v[2*c],v[2*c+1]],[dl,dh]=[v[2*d],v[2*d+1]];
    let ml=m64l(al,bl),m2=(ml*2)>>>0;[al,ah]=a64(...a64(al,ah,bl,bh),m2,0);[dl,dh]=x64(dl,dh,al,ah);[dl,dh]=r32(dl,dh);
    ml=m64l(cl,dl);m2=(ml*2)>>>0;[cl,ch]=a64(...a64(cl,ch,dl,dh),m2,0);[bl,bh]=x64(bl,bh,cl,ch);[bl,bh]=r24(bl,bh);
    ml=m64l(al,bl);m2=(ml*2)>>>0;[al,ah]=a64(...a64(al,ah,bl,bh),m2,0);[dl,dh]=x64(dl,dh,al,ah);[dl,dh]=r16(dl,dh);
    ml=m64l(cl,dl);m2=(ml*2)>>>0;[cl,ch]=a64(...a64(cl,ch,dl,dh),m2,0);[bl,bh]=x64(bl,bh,cl,ch);[bl,bh]=r63(bl,bh);
    v[2*a]=al;v[2*a+1]=ah;v[2*b]=bl;v[2*b+1]=bh;v[2*c]=cl;v[2*c+1]=ch;v[2*d]=dl;v[2*d+1]=dh;
  }
  function P(blk){
    const v=new Uint32Array(32);
    for(let col=0;col<8;col++){for(let i=0;i<16;i++){v[2*i]=blk[32*col+2*i];v[2*i+1]=blk[32*col+2*i+1];}
    GB(v,0,4,8,12);GB(v,1,5,9,13);GB(v,2,6,10,14);GB(v,3,7,11,15);GB(v,0,5,10,15);GB(v,1,6,11,12);GB(v,2,7,8,13);GB(v,3,4,9,14);
    for(let i=0;i<16;i++){blk[32*col+2*i]=v[2*i];blk[32*col+2*i+1]=v[2*i+1];}}
    for(let row=0;row<8;row++){for(let i=0;i<16;i++){v[2*i]=blk[4*row+2*i%32+(2*i>=32?256:0)];v[2*i+1]=blk[4*row+2*i%32+1+(2*i>=32?256:0)];}
    GB(v,0,4,8,12);GB(v,1,5,9,13);GB(v,2,6,10,14);GB(v,3,7,11,15);GB(v,0,5,10,15);GB(v,1,6,11,12);GB(v,2,7,8,13);GB(v,3,4,9,14);
    for(let i=0;i<16;i++){blk[4*row+2*i%32+(2*i>=32?256:0)]=v[2*i];blk[4*row+2*i%32+1+(2*i>=32?256:0)]=v[2*i+1];}}
  }
  for(let t=0;t<iterations;t++){for(let slice=0;slice<4;slice++){for(let lane=0;lane<p;lane++){
    const ec=(slice+1)*seg+(slice===0?2:0);
    for(let col=(slice===0&&t===0)?2:slice*seg;col<ec&&col<q;col++){
      const pc=col===0?q-1:col-1,R=B[lane*q+pc],J1=R[0],J2=R[1];
      const rl=(t===0&&slice===0)?lane:(J2%p);
      const rss=(rl===lane)?(slice*seg+col-1):(slice*seg+(col%seg===0?-1:0));
      const ra=Math.max(1,rss>0?rss:m-seg+(col%seg));
      const z=(ra-1-((J1*J1>>>0)%ra));
      const rs=(rl===lane&&slice===0&&t===0)?0:rl*q;
      const rca=(rs+z)%m;
      const cur=B[lane*q+col],ref=B[rca<m?rca:rca%m],tmp=new Uint32Array(256);
      for(let i=0;i<256;i++)tmp[i]=R[i]^ref[i];P(tmp);
      if(t===0){for(let i=0;i<256;i++)cur[i]=tmp[i]^R[i]^ref[i];}
      else{for(let i=0;i<256;i++)cur[i]^=tmp[i]^R[i]^ref[i];}
    }
  }}}
  const C=new Uint32Array(256);for(let lane=0;lane<p;lane++){const last=B[lane*q+q-1];for(let i=0;i<256;i++)C[i]^=last[i];}
  return _Hprime(hashLen,new Uint8Array(C.buffer,0,1024));
}

// ─── Key derivation ───────────────────────────────────────────────────────────
async function _deriveKeyArgon2id(password, salt) {
  const passBytes = _textEncoder.encode(String(password));
  const keyBytes = argon2id(passBytes, salt);
  return crypto.subtle.importKey('raw', keyBytes, { name: ZK_ALGORITHM }, false, ['encrypt', 'decrypt']);
}

async function _deriveKeyPBKDF2(password, salt) {
  const passwordKey = await crypto.subtle.importKey('raw', _textEncoder.encode(String(password)), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    passwordKey,
    { name: ZK_ALGORITHM, length: ZK_KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt file in browser before upload (Argon2id KDF, format v2)
 */
async function encryptFileZeroKnowledge(file, password) {
  try {
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const key = await _deriveKeyArgon2id(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const fileData = await file.arrayBuffer();

    const encryptedData = await crypto.subtle.encrypt({ name: ZK_ALGORITHM, iv }, key, fileData);

    // Format v2: [0x02][salt32][iv12][ciphertext]
    const combined = _concatU8([
      new Uint8Array([FORMAT_VERSION]),
      salt,
      iv,
      new Uint8Array(encryptedData)
    ]);

    const encryptedBlob = new Blob([combined], { type: 'application/octet-stream' });
    return {
      encryptedBlob,
      metadata: { originalName: file.name, originalSize: file.size, originalType: file.type, encryptedSize: encryptedBlob.size }
    };
  } catch (error) {
    console.error('Zero-knowledge encryption error:', error);
    throw new Error('Failed to encrypt file: ' + error.message);
  }
}

/**
 * Decrypt file — auto-detects format v1 (PBKDF2) vs v2 (Argon2id)
 */
async function decryptFileZeroKnowledge(encryptedBlob, password, originalName, originalType) {
  try {
    const bytes = new Uint8Array(await encryptedBlob.arrayBuffer());
    let key, iv, encryptedData;

    if (bytes[0] === FORMAT_VERSION) {
      // Format v2: Argon2id
      const salt = bytes.slice(1, 1 + SALT_LENGTH);
      iv = bytes.slice(1 + SALT_LENGTH, 1 + SALT_LENGTH + IV_LENGTH);
      encryptedData = bytes.slice(1 + SALT_LENGTH + IV_LENGTH);
      key = await _deriveKeyArgon2id(password, salt);
    } else {
      // Format v1 (legacy): PBKDF2, no version byte
      const salt = bytes.slice(0, LEGACY_SALT_LENGTH);
      iv = bytes.slice(LEGACY_SALT_LENGTH, LEGACY_SALT_LENGTH + IV_LENGTH);
      encryptedData = bytes.slice(LEGACY_SALT_LENGTH + IV_LENGTH);
      key = await _deriveKeyPBKDF2(password, salt);
    }

    const decryptedData = await crypto.subtle.decrypt({ name: ZK_ALGORITHM, iv }, key, encryptedData);
    return new Blob([decryptedData], { type: originalType || 'application/octet-stream' });
  } catch (error) {
    console.error('Zero-knowledge decryption error:', error);
    if (error.name === 'OperationError') {
      throw new Error('Decryption failed. Please check that you entered the correct password.');
    }
    throw new Error('Failed to decrypt file. Incorrect password or corrupted file.');
  }
}

/**
 * Prompt user for encryption password
 */
function promptEncryptionPassword(fileName) {
  return new Promise((resolve, reject) => {
    const password = prompt(`Enter a password to encrypt "${fileName}"\n\n⚠️ IMPORTANT: We cannot recover your files if you lose this password.\n\nPassword:`);
    if (!password || password.length < 4) {
      reject(new Error('Password must be at least 4 characters long'));
      return;
    }
    const confirm = prompt('Confirm password:');
    if (password !== confirm) {
      reject(new Error('Passwords do not match'));
      return;
    }
    resolve(password);
  });
}

/**
 * Prompt user for decryption password
 */
function promptDecryptionPassword(fileName) {
  return prompt(`Enter password to decrypt "${fileName}":`);
}

// Export functions for use in other scripts
if (typeof window !== 'undefined') {
  window.zeroKnowledgeEncrypt = encryptFileZeroKnowledge;
  window.zeroKnowledgeDecrypt = decryptFileZeroKnowledge;
  window.promptEncryptionPassword = promptEncryptionPassword;
  window.promptDecryptionPassword = promptDecryptionPassword;
  window.argon2id = argon2id;
}

