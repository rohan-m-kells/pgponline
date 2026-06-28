// Initialize OpenPGP
openpgp.config.rejectCurves = new Set();

// Tab Navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tabName = btn.getAttribute('data-tab');
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Deactivate all buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById(tabName).classList.add('active');
    
    // Activate selected button
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
}

// Copy to Clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    
    const btn = event.target;
    const originalText = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => {
        btn.textContent = originalText;
    }, 2000);
}

// Generate Keys
document.getElementById('generateBtn').addEventListener('click', generateKeys);

async function generateKeys() {
    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const passphrase = document.getElementById('passphrase').value;
    const keySize = parseInt(document.getElementById('keySize').value);

    if (!name || !email || !passphrase) {
        alert('Please fill in all fields');
        return;
    }

    if (passphrase.length < 8) {
        alert('Passphrase must be at least 8 characters');
        return;
    }

    const generateBtn = document.getElementById('generateBtn');
    const progressBar = document.getElementById('generateProgress');
    
    generateBtn.disabled = true;
    progressBar.style.display = 'block';

    try {
        const { publicKey, privateKey } = await openpgp.generateKey({
            type: 'rsa',
            rsaBits: keySize,
            userIDs: [{ name: name, email: email }],
            passphrase: passphrase,
            format: 'armored'
        });

        document.getElementById('publicKeyOutput').value = publicKey;
        document.getElementById('privateKeyOutput').value = privateKey;

        alert('Keys generated successfully!');
    } catch (error) {
        alert('Error generating keys: ' + error.message);
        console.error(error);
    } finally {
        generateBtn.disabled = false;
        progressBar.style.display = 'none';
    }
}

// Encrypt Message
document.getElementById('encryptBtn').addEventListener('click', encryptMessage);

async function encryptMessage() {
    const publicKeyArmored = document.getElementById('recipientPublicKey').value.trim();
    const messageText = document.getElementById('messageToEncrypt').value.trim();

    if (!publicKeyArmored || !messageText) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = await openpgp.createMessage({ text: messageText });
        const encrypted = await openpgp.encrypt({
            message: message,
            encryptionKeys: publicKey
        });

        document.getElementById('encryptedOutput').value = encrypted;
    } catch (error) {
        alert('Error encrypting message: ' + error.message);
        console.error(error);
    }
}

// Decrypt Message
document.getElementById('decryptBtn').addEventListener('click', decryptMessage);

async function decryptMessage() {
    const privateKeyArmored = document.getElementById('privateKeyForDecrypt').value.trim();
    const passphrase = document.getElementById('passphraseForDecrypt').value;
    const encryptedMessageText = document.getElementById('messageToDecrypt').value.trim();

    if (!privateKeyArmored || !passphrase || !encryptedMessageText) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const privateKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
            passphrase: passphrase
        });

        const message = await openpgp.readMessage({
            armoredMessage: encryptedMessageText
        });

        const { data: decrypted } = await openpgp.decrypt({
            message: message,
            decryptionKeys: privateKey
        });

        document.getElementById('decryptedOutput').value = decrypted;
    } catch (error) {
        alert('Error decrypting message: ' + error.message);
        console.error(error);
    }
}

// Sign Message
document.getElementById('signBtn').addEventListener('click', signMessage);

async function signMessage() {
    const privateKeyArmored = document.getElementById('privateKeyForSign').value.trim();
    const passphrase = document.getElementById('passphraseForSign').value;
    const messageText = document.getElementById('messageToSign').value.trim();

    if (!privateKeyArmored || !passphrase || !messageText) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const privateKey = await openpgp.decryptKey({
            privateKey: await openpgp.readPrivateKey({ armoredKey: privateKeyArmored }),
            passphrase: passphrase
        });

        const message = await openpgp.createMessage({ text: messageText });
        const detachedSignature = await openpgp.sign({
            message: message,
            signingKeys: privateKey,
            detached: true
        });

        document.getElementById('signatureOutput').value = detachedSignature;
    } catch (error) {
        alert('Error signing message: ' + error.message);
        console.error(error);
    }
}

// Verify Signature
document.getElementById('verifyBtn').addEventListener('click', verifySignature);

async function verifySignature() {
    const publicKeyArmored = document.getElementById('publicKeyForVerify').value.trim();
    const messageText = document.getElementById('messageToVerify').value.trim();
    const signatureArmored = document.getElementById('signatureToVerify').value.trim();

    if (!publicKeyArmored || !messageText || !signatureArmored) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
        const message = await openpgp.createMessage({ text: messageText });
        const signature = await openpgp.readSignature({ armoredSignature: signatureArmored });

        const verificationResult = await openpgp.verify({
            message: message,
            signature: signature,
            verificationKeys: publicKey
        });

        const resultDiv = document.getElementById('verifyResult');
        const isValid = verificationResult.signatures[0].valid;

        if (isValid) {
            resultDiv.className = 'verify-result success';
            resultDiv.innerHTML = '✓ Signature is valid! This message was signed by the claimed signer and has not been modified.';
        } else {
            resultDiv.className = 'verify-result error';
            resultDiv.innerHTML = '✗ Signature is invalid! This message may have been modified or was not signed by the claimed signer.';
        }
        resultDiv.style.display = 'block';
    } catch (error) {
        const resultDiv = document.getElementById('verifyResult');
        resultDiv.className = 'verify-result error';
        resultDiv.innerHTML = '✗ Error verifying signature: ' + error.message;
        resultDiv.style.display = 'block';
        console.error(error);
    }
}
