// script.js — handles OpenPGP operations using openpgp.js v5
(async () => {
  // Ensure library is ready
  if (window.openpgp && openpgp.initWorker) {
    try { await openpgp.initWorker({}); } catch (e) { /* worker optional */ }
  }

  // helpers
  const $ = id => document.getElementById(id);
  const uidEl = $('uid');
  const passEl = $('passphrase');
  const pubEl = $('publicKey');
  const privEl = $('privateKey');

  const plaintextEl = $('plaintext');
  const ciphertextEl = $('ciphertext');
  const recipientPubEl = $('recipientPub');
  const recipientPrivEl = $('recipientPriv');
  const recipientPassEl = $('recipientPass');

  const signPrivEl = $('signPriv');
  const signPassEl = $('signPass');
  const verifyPubEl = $('verifyPub');

  // Buttons
  $('genKey').addEventListener('click', generateKeypair);
  $('clearKeys').addEventListener('click', () => { pubEl.value = ''; privEl.value = ''; });
  $('encrypt').addEventListener('click', encryptMessage);
  $('decrypt').addEventListener('click', decryptMessage);
  $('sign').addEventListener('click', signDetached);
  $('verify').addEventListener('click', verifyDetached);

  async function generateKeypair(){
    try{
      const nameEmail = uidEl.value || 'User <user@example.com>';
      const passphrase = passEl.value || '';
      // attempt to split name and email
      let userIDs = [{name: nameEmail}];
      // Use modern ECC (curve: ed25519) for compact keys
      const key = await openpgp.generateKey({
        type: 'ecc',
        curve: 'ed25519',
        userIDs: userIDs,
        passphrase: passphrase,
      });
      pubEl.value = key.publicKey;
      privEl.value = key.privateKey;
      alert('Keypair generated. Copy your keys and keep your private key safe.');
    }catch(err){
      console.error(err);
      alert('Error generating key: ' + err.message);
    }
  }

  async function encryptMessage(){
    try{
      const plaintext = plaintextEl.value || '';
      if(!plaintext){ alert('Enter plaintext to encrypt'); return; }
      const armoredPub = recipientPubEl.value || pubEl.value;
      if(!armoredPub){ alert('Provide recipient public key (paste in Recipient Public Key or generate one).'); return; }

      // read public key
      const pubKey = await openpgp.readKey({ armoredKey: armoredPub });
      const message = await openpgp.createMessage({ text: plaintext });
      const encrypted = await openpgp.encrypt({ message, encryptionKeys: pubKey });
      ciphertextEl.value = encrypted.data;
    }catch(err){
      console.error(err);
      alert('Encryption error: ' + err.message);
    }
  }

  async function decryptMessage(){
    try{
      const armoredPriv = recipientPrivEl.value || privEl.value;
      const encrypted = ciphertextEl.value || '';
      if(!armoredPriv){ alert('Provide private key to decrypt (Recipient Private Key or generated private key).'); return; }
      if(!encrypted){ alert('Paste ciphertext into the Ciphertext box to decrypt.'); return; }

      let privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPriv });
      const pass = recipientPassEl.value || '';
      if(pass){
        privateKey = await openpgp.decryptKey({ privateKey, passphrase: pass });
      }
      const message = await openpgp.readMessage({ armoredMessage: encrypted });
      const { data: decrypted } = await openpgp.decrypt({ message, decryptionKeys: privateKey });
      ciphertextEl.value = decrypted;
    }catch(err){
      console.error(err);
      alert('Decryption error: ' + err.message);
    }
  }

  async function signDetached(){
    try{
      const armoredPriv = signPrivEl.value || privEl.value;
      const pass = signPassEl.value || passEl.value || '';
      const data = plaintextEl.value || '';
      if(!armoredPriv){ alert('Provide private key to sign with'); return; }
      if(!data){ alert('Enter plaintext to sign'); return; }

      let privateKey = await openpgp.readPrivateKey({ armoredKey: armoredPriv });
      if(pass){ privateKey = await openpgp.decryptKey({ privateKey, passphrase: pass }); }
      const message = await openpgp.createMessage({ text: data });
      const detached = await openpgp.sign({ message, signingKeys: privateKey, detached: true });
      ciphertextEl.value = detached; // put detached signature into ciphertext box
    }catch(err){
      console.error(err);
      alert('Signing error: ' + err.message);
    }
  }

  async function verifyDetached(){
    try{
      const armoredPub = verifyPubEl.value || pubEl.value;
      const sig = ciphertextEl.value || '';
      const data = plaintextEl.value || '';
      if(!armoredPub){ alert('Provide public key to verify with'); return; }
      if(!sig){ alert('Put detached signature into Ciphertext box'); return; }
      if(!data){ alert('Put the signed plaintext into Plaintext box to verify'); return; }

      const publicKey = await openpgp.readKey({ armoredKey: armoredPub });
      const message = await openpgp.createMessage({ text: data });
      const signature = await openpgp.readSignature({ armoredSignature: sig });
      const verification = await openpgp.verify({ message, signature, verificationKeys: publicKey });
      const { signatures } = verification;
      // Check if signature is valid
      if (signatures && signatures.length > 0 && signatures[0].verified) {
        alert('Signature is valid');
      } else {
        alert('Signature verification failed');
      }
    }catch(err){
      console.error(err);
      alert('Verification failed: ' + (err.message || err));
    }
  }

})();
