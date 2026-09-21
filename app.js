"use strict";

/* =====================================================
   CONFIGURATION
===================================================== */

const STORAGE_KEY = "securevault_v2";

const PBKDF2_ITERATIONS = 600000;

const VERIFIER_TEXT =
    "SECUREVAULT_MASTER_PASSWORD_VERIFIER_2026";


/* =====================================================
   ETAT DE L'APPLICATION
===================================================== */

let vaultKey = null;

let vaultData = {
    version: 2,
    salt: null,
    verifier: null,
    passwords: []
};


/* =====================================================
   DOM
===================================================== */

const authPage =
    document.getElementById("authPage");

const appPage =
    document.getElementById("appPage");

const setupBox =
    document.getElementById("setupBox");

const loginBox =
    document.getElementById("loginBox");

const setupForm =
    document.getElementById("setupForm");

const loginForm =
    document.getElementById("loginForm");

const passwordForm =
    document.getElementById("passwordForm");

const passwordModal =
    document.getElementById("passwordModal");

const generatorModal =
    document.getElementById("generatorModal");

const passwordList =
    document.getElementById("passwordList");

const emptyState =
    document.getElementById("emptyState");

const searchInput =
    document.getElementById("searchInput");

const toast =
    document.getElementById("toast");


/* =====================================================
   INITIALISATION
===================================================== */

document.addEventListener(
    "DOMContentLoaded",
    initialize
);


function initialize() {

    loadVault();

    setupEventListeners();

    updateAuthScreen();

    setupPasswordStrengthListeners();

}


/* =====================================================
   EVENEMENTS
===================================================== */

function setupEventListeners() {

    setupForm.addEventListener(
        "submit",
        createVault
    );


    loginForm.addEventListener(
        "submit",
        unlockVault
    );


    passwordForm.addEventListener(
        "submit",
        savePassword
    );


    document
        .getElementById("lockButton")
        .addEventListener(
            "click",
            lockVault
        );


    document
        .getElementById("addPasswordButton")
        .addEventListener(
            "click",
            () => openPasswordModal()
        );


    document
        .getElementById("emptyAddButton")
        .addEventListener(
            "click",
            () => openPasswordModal()
        );


    document
        .getElementById("generateButton")
        .addEventListener(
            "click",
            openGenerator
        );


    document
        .getElementById("generatePasswordButton")
        .addEventListener(
            "click",
            openGenerator
        );


    document
        .getElementById("closeModal")
        .addEventListener(
            "click",
            closePasswordModal
        );


    document
        .getElementById("cancelModal")
        .addEventListener(
            "click",
            closePasswordModal
        );


    document
        .getElementById("closeGenerator")
        .addEventListener(
            "click",
            closeGenerator
        );


    document
        .getElementById("regenerateButton")
        .addEventListener(
            "click",
            generateGeneratorPassword
        );


    document
        .getElementById("useGeneratedPassword")
        .addEventListener(
            "click",
            useGeneratedPassword
        );


    document
        .getElementById("copyGeneratedPassword")
        .addEventListener(
            "click",
            copyGeneratedPassword
        );


    document
        .getElementById("passwordLength")
        .addEventListener(
            "input",
            () => {

                document
                    .getElementById(
                        "passwordLengthValue"
                    )
                    .textContent =
                    document
                        .getElementById(
                            "passwordLength"
                        )
                        .value;

                generateGeneratorPassword();

            }
        );


    searchInput.addEventListener(
        "input",
        displayPasswords
    );


    document
        .getElementById("accountPassword")
        .addEventListener(
            "input",
            function () {

                showPasswordStrength(
                    this.value,
                    "accountPasswordStrength"
                );

            }
        );


    document
        .getElementById("setupPassword")
        .addEventListener(
            "input",
            function () {

                showPasswordStrength(
                    this.value,
                    "setupPasswordStrength"
                );

            }
        );


    document
        .querySelectorAll(".eye-button")
        .forEach(button => {

            button.addEventListener(
                "click",
                () => {

                    togglePassword(
                        button.dataset.target
                    );

                }
            );

        });


    window.addEventListener(
        "keydown",
        event => {

            if (event.key === "Escape") {

                closePasswordModal();

                closeGenerator();

            }

        }
    );


    passwordModal.addEventListener(
        "click",
        event => {

            if (
                event.target === passwordModal
            ) {

                closePasswordModal();

            }

        }
    );


    generatorModal.addEventListener(
        "click",
        event => {

            if (
                event.target === generatorModal
            ) {

                closeGenerator();

            }

        }
    );

}


/* =====================================================
   LOCAL STORAGE
===================================================== */

function loadVault() {

    const saved =
        localStorage.getItem(
            STORAGE_KEY
        );

    if (!saved) {

        vaultData = {
            version: 2,
            salt: null,
            verifier: null,
            passwords: []
        };

        return;
    }


    try {

        const parsed =
            JSON.parse(saved);

        vaultData = parsed;

        if (!Array.isArray(vaultData.passwords)) {

            vaultData.passwords = [];

        }

    } catch (error) {

        console.error(error);

        vaultData = {
            version: 2,
            salt: null,
            verifier: null,
            passwords: []
        };

    }

}


function persistVault() {

    localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify(vaultData)
    );

}


/* =====================================================
   ECRAN AUTHENTIFICATION
===================================================== */

function updateAuthScreen() {

    if (
        vaultData.salt &&
        vaultData.verifier
    ) {

        setupBox.classList.add("hidden");

        loginBox.classList.remove("hidden");

    } else {

        setupBox.classList.remove("hidden");

        loginBox.classList.add("hidden");

    }

}


/* =====================================================
   CREATION DU COFFRE
===================================================== */

async function createVault(event) {

    event.preventDefault();

    clearAuthMessage();


    const password =
        document.getElementById(
            "setupPassword"
        ).value;


    const confirmation =
        document.getElementById(
            "setupPasswordConfirm"
        ).value;


    if (password.length < 8) {

        showAuthMessage(
            "Le mot de passe maître doit contenir au moins 8 caractères.",
            "error"
        );

        return;
    }


    if (password !== confirmation) {

        showAuthMessage(
            "Les deux mots de passe ne correspondent pas.",
            "error"
        );

        return;
    }


    try {

        const salt =
            crypto.getRandomValues(
                new Uint8Array(16)
            );


        vaultKey =
            await deriveKey(
                password,
                salt
            );


        const verifier =
            await encryptText(
                VERIFIER_TEXT,
                vaultKey
            );


        vaultData = {

            version: 2,

            salt:
                bytesToBase64(salt),

            verifier,

            passwords: []

        };


        persistVault();


        masterPasswordCleanup();


        showAuthMessage(
            "Coffre-fort créé avec succès.",
            "success"
        );


        setTimeout(() => {

            showApp();

        }, 400);


    } catch (error) {

        console.error(error);

        showAuthMessage(
            "Impossible de créer le coffre-fort.",
            "error"
        );

    }

}


/* =====================================================
   DEVERROUILLAGE
===================================================== */

async function unlockVault(event) {

    event.preventDefault();

    clearAuthMessage();


    const password =
        document.getElementById(
            "loginPassword"
        ).value;


    if (!password) {

        return;

    }


    try {

        const salt =
            base64ToBytes(
                vaultData.salt
            );


        const key =
            await deriveKey(
                password,
                salt
            );


        const verifier =
            await decryptText(
                vaultData.verifier,
                key
            );


        if (
            verifier !==
            VERIFIER_TEXT
        ) {

            throw new Error(
                "Mot de passe incorrect."
            );

        }


        vaultKey = key;

        document
            .getElementById(
                "loginPassword"
            )
            .value = "";


        showApp();


    } catch (error) {

        console.error(error);

        showAuthMessage(
            "Mot de passe maître incorrect.",
            "error"
        );

    }

}


/* =====================================================
   VERROUILLAGE
===================================================== */

function lockVault() {

    vaultKey = null;

    document
        .getElementById(
            "loginPassword"
        )
        .value = "";


    appPage.classList.add("hidden");

    authPage.classList.remove("hidden");

    updateAuthScreen();


    searchInput.value = "";


    showToast(
        "Coffre-fort verrouillé.",
        "success"
    );

}


function masterPasswordCleanup() {

    document
        .getElementById(
            "setupPassword"
        )
        .value = "";

    document
        .getElementById(
            "setupPasswordConfirm"
        )
        .value = "";

}


/* =====================================================
   AFFICHER APPLICATION
===================================================== */

async function showApp() {

    authPage.classList.add("hidden");

    appPage.classList.remove("hidden");

    await displayPasswords();

    updateStatistics();

}


/* =====================================================
   DERIVATION CLE AES
===================================================== */

async function deriveKey(
    password,
    salt
) {

    const encoder =
        new TextEncoder();


    const passwordKey =
        await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            {
                name: "PBKDF2"
            },
            false,
            [
                "deriveKey"
            ]
        );


    return crypto.subtle.deriveKey(

        {

            name: "PBKDF2",

            salt,

            iterations:
                PBKDF2_ITERATIONS,

            hash:
                "SHA-256"

        },

        passwordKey,

        {

            name: "AES-GCM",

            length: 256

        },

        false,

        [
            "encrypt",
            "decrypt"
        ]

    );

}


/* =====================================================
   CHIFFREMENT AES-256-GCM
===================================================== */

async function encryptText(
    text,
    key
) {

    const encoder =
        new TextEncoder();


    const iv =
        crypto.getRandomValues(
            new Uint8Array(12)
        );


    const encrypted =
        await crypto.subtle.encrypt(

            {

                name: "AES-GCM",

                iv

            },

            key,

            encoder.encode(text)

        );


    return {

        iv:
            bytesToBase64(iv),

        data:
            bytesToBase64(
                new Uint8Array(
                    encrypted
                )
            )

    };

}


/* =====================================================
   DECHIFFREMENT
===================================================== */

async function decryptText(
    encryptedObject,
    key
) {

    const iv =
        base64ToBytes(
            encryptedObject.iv
        );


    const encrypted =
        base64ToBytes(
            encryptedObject.data
        );


    const decrypted =
        await crypto.subtle.decrypt(

            {

                name: "AES-GCM",

                iv

            },

            key,

            encrypted

        );


    return new TextDecoder()
        .decode(decrypted);

}


/* =====================================================
   BASE64
===================================================== */

function bytesToBase64(bytes) {

    let binary = "";

    const chunkSize = 0x8000;

    for (
        let i = 0;
        i < bytes.length;
        i += chunkSize
    ) {

        binary += String.fromCharCode(
            ...bytes.subarray(
                i,
                Math.min(
                    i + chunkSize,
                    bytes.length
                )
            )
        );

    }

    return btoa(binary);

}


function base64ToBytes(base64) {

    const binary =
        atob(base64);

    const bytes =
        new Uint8Array(
            binary.length
        );


    for (
        let i = 0;
        i < binary.length;
        i++
    ) {

        bytes[i] =
            binary.charCodeAt(i);

    }


    return bytes;

}


/* =====================================================
   AJOUT / MODIFICATION
===================================================== */

async function savePassword(event) {

    event.preventDefault();


    if (!vaultKey) {

        showToast(
            "Le coffre est verrouillé.",
            "error"
        );

        return;

    }


    const id =
        document
            .getElementById(
                "editId"
            )
            .value;


    const site =
        document
            .getElementById(
                "siteName"
            )
            .value
            .trim();


    const url =
        document
            .getElementById(
                "siteUrl"
            )
            .value
            .trim();


    const username =
        document
            .getElementById(
                "username"
            )
            .value
            .trim();


    const password =
        document
            .getElementById(
                "accountPassword"
            )
            .value;


    const notes =
        document
            .getElementById(
                "notes"
            )
            .value
            .trim();


    if (!site || !password) {

        showToast(
            "Le site et le mot de passe sont obligatoires.",
            "error"
        );

        return;

    }


    try {

        /*
         * Le mot de passe est chiffré
         * avant d'être enregistré.
         */

        const encryptedPassword =
            await encryptText(
                password,
                vaultKey
            );


        /*
         * Les notes peuvent également
         * contenir des informations sensibles.
         */

        let encryptedNotes = null;


        if (notes) {

            encryptedNotes =
                await encryptText(
                    notes,
                    vaultKey
                );

        }


        const item = {

            id:
                id
                    ? id
                    : crypto.randomUUID(),

            site,

            url,

            username,

            password:
                encryptedPassword,

            notes:
                encryptedNotes,

            createdAt:
                id
                    ? getExistingDate(id)
                    : new Date().toISOString(),

            updatedAt:
                new Date().toISOString()

        };


        if (id) {

            const index =
                vaultData.passwords.findIndex(
                    item =>
                        item.id === id
                );


            if (index !== -1) {

                vaultData.passwords[index] =
                    item;

            }

        } else {

            vaultData.passwords.push(
                item
            );

        }


        persistVault();

        closePasswordModal();

        await displayPasswords();

        updateStatistics();


        showToast(
            id
                ? "Compte modifié."
                : "Compte ajouté.",
            "success"
        );


    } catch (error) {

        console.error(error);

        showToast(
            "Erreur lors de l'enregistrement.",
            "error"
        );

    }

}


function getExistingDate(id) {

    const item =
        vaultData.passwords.find(
            item =>
                item.id === id
        );


    return item?.createdAt ||
        new Date().toISOString();

}


/* =====================================================
   AFFICHAGE DES COMPTES
===================================================== */

async function displayPasswords() {

    if (!vaultKey) {

        return;

    }


    passwordList.innerHTML = "";


    const search =
        searchInput.value
            .trim()
            .toLowerCase();


    const filtered =
        vaultData.passwords.filter(
            item => {

                return (

                    item.site
                        .toLowerCase()
                        .includes(search)

                    ||

                    item.username
                        .toLowerCase()
                        .includes(search)

                );

            }
        );


    if (
        filtered.length === 0
    ) {

        passwordList.classList.add(
            "hidden"
        );

        emptyState.classList.remove(
            "hidden"
        );


        if (
            search
        ) {

            emptyState.innerHTML = `

                <div class="empty-icon">
                    🔎
                </div>

                <h3>
                    Aucun résultat
                </h3>

                <p>
                    Aucun compte ne correspond à
                    votre recherche.
                </p>

            `;

        } else {

            emptyState.innerHTML = `

                <div class="empty-icon">
                    🔐
                </div>

                <h3>
                    Votre coffre-fort est vide
                </h3>

                <p>
                    Ajoutez votre premier compte
                    pour commencer.
                </p>

                <button
                    id="emptyAddButton"
                    class="btn btn-primary"
                >
                    ＋ Ajouter un compte
                </button>

            `;


            document
                .getElementById(
                    "emptyAddButton"
                )
                .addEventListener(
                    "click",
                    () => openPasswordModal()
                );

        }

        return;

    }


    passwordList.classList.remove(
        "hidden"
    );

    emptyState.classList.add(
        "hidden"
    );


    for (
        const item of filtered
    ) {

        let password = "";

        try {

            password =
                await decryptText(
                    item.password,
                    vaultKey
                );

        } catch {

            password =
                "[Erreur de déchiffrement]";

        }


        const card =
            createPasswordCard(
                item,
                password
            );


        passwordList.appendChild(
            card
        );

    }

}


/* =====================================================
   CREATION CARTE
===================================================== */

function createPasswordCard(
    item,
    password
) {

    const card =
        document.createElement(
            "article"
        );


    card.className =
        "password-card";


    card.innerHTML = `

        <div class="card-top">

            <div class="site-info">

                <div class="site-icon">
                    ${getSiteIcon(item.site)}
                </div>

                <div>

                    <h3 class="site-name">
                        ${escapeHTML(item.site)}
                    </h3>

                    ${
                        item.url
                            ? `
                            <div class="site-url">
                                ${escapeHTML(item.url)}
                            </div>
                            `
                            : ""
                    }

                </div>

            </div>


            <div class="card-menu">

                <button
                    class="icon-button"
                    title="Modifier"
                    data-action="edit"
                >
                    ✏️
                </button>


                <button
                    class="icon-button delete"
                    title="Supprimer"
                    data-action="delete"
                >
                    🗑️
                </button>

            </div>

        </div>


        <div class="card-field">

            <span class="field-label">
                Identifiant
            </span>

            <div class="field-value">

                <span>
                    ${
                        escapeHTML(
                            item.username ||
                            "Non renseigné"
                        )
                    }
                </span>


                ${
                    item.username
                        ? `
                        <button
                            class="copy-small"
                            data-action="copy-username"
                        >
                            📋
                        </button>
                        `
                        : ""
                }

            </div>

        </div>


        <div class="card-field">

            <span class="field-label">
                Mot de passe
            </span>

            <div class="field-value">

                <span
                    class="password-display"
                    data-password="hidden"
                >
                    ••••••••••••
                </span>


                <button
                    class="copy-small"
                    data-action="toggle-password"
                >
                    👁
                </button>

            </div>

        </div>


        <div class="card-actions">

            <button
                class="card-action"
                data-action="copy-password"
            >
                📋 Copier
            </button>


            ${
                item.url
                    ? `
                    <button
                        class="card-action"
                        data-action="open-site"
                    >
                        🌐 Ouvrir
                    </button>
                    `
                    : ""
            }

        </div>

    `;


    const passwordDisplay =
        card.querySelector(
            ".password-display"
        );


    const editButton =
        card.querySelector(
            '[data-action="edit"]'
        );


    const deleteButton =
        card.querySelector(
            '[data-action="delete"]'
        );


    const copyUsernameButton =
        card.querySelector(
            '[data-action="copy-username"]'
        );


    const toggleButton =
        card.querySelector(
            '[data-action="toggle-password"]'
        );


    const copyPasswordButton =
        card.querySelector(
            '[data-action="copy-password"]'
        );


    const openSiteButton =
        card.querySelector(
            '[data-action="open-site"]'
        );


    editButton.addEventListener(
        "click",
        () => editPassword(item.id)
    );


    deleteButton.addEventListener(
        "click",
        () => deletePassword(item.id)
    );


    if (copyUsernameButton) {

        copyUsernameButton.addEventListener(
            "click",
            () => {

                copyText(
                    item.username
                );

            }
        );

    }


    toggleButton.addEventListener(
        "click",
        () => {

            if (
                passwordDisplay.dataset.password ===
                "hidden"
            ) {

                passwordDisplay.textContent =
                    password;

                passwordDisplay.dataset.password =
                    "visible";

                toggleButton.textContent =
                    "🙈";

            } else {

                passwordDisplay.textContent =
                    "••••••••••••";

                passwordDisplay.dataset.password =
                    "hidden";

                toggleButton.textContent =
                    "👁";

            }

        }
    );


    copyPasswordButton.addEventListener(
        "click",
        () => {

            copyText(password);

        }
    );


    if (openSiteButton) {

        openSiteButton.addEventListener(
            "click",
            () => {

                let url = item.url;

                if (
                    !url.startsWith("http://") &&
                    !url.startsWith("https://")
                ) {

                    url =
                        "https://" + url;

                }


                window.open(
                    url,
                    "_blank",
                    "noopener,noreferrer"
                );

            }
        );

    }


    return card;

}


/* =====================================================
   EDITER
===================================================== */

async function editPassword(id) {

    const item =
        vaultData.passwords.find(
            item =>
                item.id === id
        );


    if (!item) {

        return;

    }


    try {

        const password =
            await decryptText(
                item.password,
                vaultKey
            );


        let notes = "";


        if (item.notes) {

            notes =
                await decryptText(
                    item.notes,
                    vaultKey
                );

        }


        document
            .getElementById(
                "editId"
            )
            .value = item.id;


        document
            .getElementById(
                "siteName"
            )
            .value = item.site;


        document
            .getElementById(
                "siteUrl"
            )
            .value = item.url || "";


        document
            .getElementById(
                "username"
            )
            .value = item.username || "";


        document
            .getElementById(
                "accountPassword"
            )
            .value = password;


        document
            .getElementById(
                "notes"
            )
            .value = notes;


        document
            .getElementById(
                "modalTitle"
            )
            .textContent =
            "Modifier un compte";


        showPasswordStrength(
            password,
            "accountPasswordStrength"
        );


        openPasswordModal();

    } catch (error) {

        console.error(error);

        showToast(
            "Impossible de déchiffrer ce compte.",
            "error"
        );

    }

}


/* =====================================================
   SUPPRIMER
===================================================== */

async function deletePassword(id) {

    const item =
        vaultData.passwords.find(
            item =>
                item.id === id
        );


    if (!item) {

        return;

    }


    const confirmed =
        confirm(
            `Supprimer définitivement le compte "${item.site}" ?`
        );


    if (!confirmed) {

        return;

    }


    vaultData.passwords =
        vaultData.passwords.filter(
            item =>
                item.id !== id
        );


    persistVault();

    await displayPasswords();

    updateStatistics();


    showToast(
        "Compte supprimé.",
        "success"
    );

}


/* =====================================================
   MODAL PASSWORD
===================================================== */

function openPasswordModal() {

    passwordModal.classList.remove(
        "hidden"
    );


    document
        .getElementById(
            "siteName"
        )
        .focus();

}


function closePasswordModal() {

    passwordModal.classList.add(
        "hidden"
    );


    passwordForm.reset();


    document
        .getElementById(
            "editId"
        )
        .value = "";


    document
        .getElementById(
            "modalTitle"
        )
        .textContent =
        "Ajouter un compte";


    document
        .getElementById(
            "accountPasswordStrength"
        )
        .textContent = "";

}


/* =====================================================
   GENERATEUR
===================================================== */

function openGenerator() {

    generatorModal.classList.remove(
        "hidden"
    );


    generateGeneratorPassword();

}


function closeGenerator() {

    generatorModal.classList.add(
        "hidden"
    );

}


function generateGeneratorPassword() {

    const length =
        Number(
            document
                .getElementById(
                    "passwordLength"
                )
                .value
        );


    const includeUppercase =
        document
            .getElementById(
                "includeUppercase"
            )
            .checked;


    const includeLowercase =
        document
            .getElementById(
                "includeLowercase"
            )
            .checked;


    const includeNumbers =
        document
            .getElementById(
                "includeNumbers"
            )
            .checked;


    const includeSymbols =
        document
            .getElementById(
                "includeSymbols"
            )
            .checked;


    let groups = [];


    if (includeUppercase) {

        groups.push(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        );

    }


    if (includeLowercase) {

        groups.push(
            "abcdefghijklmnopqrstuvwxyz"
        );

    }


    if (includeNumbers) {

        groups.push(
            "0123456789"
        );

    }


    if (includeSymbols) {

        groups.push(
            "!@#$%^&*()-_=+[]{};:,.?"
        );

    }


    if (groups.length === 0) {

        showToast(
            "Sélectionnez au moins un type de caractère.",
            "error"
        );

        return;

    }


    let password = "";


    /*
     * On prend au moins un caractère
     * dans chaque groupe sélectionné.
     */

    groups.forEach(
        group => {

            password +=
                randomCharacter(group);

        }
    );


    const allCharacters =
        groups.join("");


    while (
        password.length < length
    ) {

        password +=
            randomCharacter(
                allCharacters
            );

    }


    password =
        secureShuffle(password);


    document
        .getElementById(
            "generatedPassword"
        )
        .value =
        password;

}


function randomCharacter(
    characters
) {

    const random =
        new Uint32Array(1);


    crypto.getRandomValues(
        random
    );


    return characters[
        random[0] %
        characters.length
    ];

}


/* =====================================================
   MELANGE SECURISE
===================================================== */

function secureShuffle(
    value
) {

    const array =
        value.split("");


    for (
        let i = array.length - 1;
        i > 0;
        i--
    ) {

        const random =
            new Uint32Array(1);


        crypto.getRandomValues(
            random
        );


        const j =
            random[0] %
            (i + 1);


        [
            array[i],
            array[j]
        ] =
        [
            array[j],
            array[i]
        ];

    }


    return array.join("");

}


/* =====================================================
   UTILISER GENERATEUR
===================================================== */

function useGeneratedPassword() {

    const password =
        document
            .getElementById(
                "generatedPassword"
            )
            .value;


    document
        .getElementById(
            "accountPassword"
        )
        .value =
        password;


    showPasswordStrength(
        password,
        "accountPasswordStrength"
    );


    closeGenerator();

    openPasswordModal();

}


/* =====================================================
   COPIER GENERATEUR
===================================================== */

async function copyGeneratedPassword() {

    const password =
        document
            .getElementById(
                "generatedPassword"
            )
            .value;


    await copyText(password);

}


/* =====================================================
   COPIER
===================================================== */

async function copyText(text) {

    if (!text) {

        return;

    }


    try {

        await navigator.clipboard.writeText(
            text
        );


        showToast(
            "Copié dans le presse-papiers.",
            "success"
        );


    } catch (error) {

        console.error(error);

        showToast(
            "Impossible de copier.",
            "error"
        );

    }

}


/* =====================================================
   STATISTIQUES
===================================================== */

function updateStatistics() {

    const total =
        vaultData.passwords.length;


    const sites =
        new Set(
            vaultData.passwords.map(
                item =>
                    item.site.toLowerCase()
            )
        ).size;


    document
        .getElementById(
            "totalPasswords"
        )
        .textContent =
        total;


    document
        .getElementById(
            "totalSites"
        )
        .textContent =
        sites;

}


/* =====================================================
   MOT DE PASSE / VISIBILITE
===================================================== */

function togglePassword(id) {

    const input =
        document.getElementById(id);


    if (
        input.type === "password"
    ) {

        input.type = "text";

    } else {

        input.type = "password";

    }

}


/* =====================================================
   FORCE MOT DE PASSE
===================================================== */

function showPasswordStrength(
    password,
    elementId
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!password) {

        element.textContent = "";

        element.className =
            "password-strength";

        return;

    }


    let score = 0;


    if (password.length >= 8) {

        score++;

    }


    if (password.length >= 12) {

        score++;

    }


    if (/[A-Z]/.test(password)) {

        score++;

    }


    if (/[a-z]/.test(password)) {

        score++;

    }


    if (/[0-9]/.test(password)) {

        score++;

    }


    if (/[^A-Za-z0-9]/.test(password)) {

        score++;

    }


    element.className =
        "password-strength";


    if (score <= 2) {

        element.textContent =
            "Faible";

        element.classList.add(
            "strength-weak"
        );

    } else if (score <= 4) {

        element.textContent =
            "Moyen";

        element.classList.add(
            "strength-medium"
        );

    } else if (score === 5) {

        element.textContent =
            "Bon";

        element.classList.add(
            "strength-good"
        );

    } else {

        element.textContent =
            "Très fort";

        element.classList.add(
            "strength-strong"
        );

    }

}


function setupPasswordStrengthListeners() {

    showPasswordStrength(
        document
            .getElementById(
                "setupPassword"
            )
            .value,
        "setupPasswordStrength"
    );

}


/* =====================================================
   ICONES
===================================================== */

function getSiteIcon(site) {

    const name =
        site.toLowerCase();


    if (
        name.includes("google") ||
        name.includes("gmail")
    ) {

        return "📧";

    }


    if (
        name.includes("facebook") ||
        name.includes("meta")
    ) {

        return "📘";

    }


    if (
        name.includes("instagram")
    ) {

        return "📸";

    }


    if (
        name.includes("github")
    ) {

        return "💻";

    }


    if (
        name.includes("linkedin")
    ) {

        return "💼";

    }


    if (
        name.includes("youtube")
    ) {

        return "▶️";

    }


    if (
        name.includes("microsoft") ||
        name.includes("outlook")
    ) {

        return "📨";

    }


    return "🔐";

}


/* =====================================================
   SECURITE HTML
===================================================== */

function escapeHTML(value) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        value ?? "";


    return div.innerHTML;

}


/* =====================================================
   MESSAGES
===================================================== */

function showAuthMessage(
    message,
    type
) {

    const element =
        document.getElementById(
            "authMessage"
        );


    element.textContent =
        message;


    element.className =
        "auth-message " +
        type;

}


function clearAuthMessage() {

    const element =
        document.getElementById(
            "authMessage"
        );


    element.textContent = "";

    element.className =
        "auth-message";

}


let toastTimer = null;


function showToast(
    message,
    type = "success"
) {

    toast.textContent =
        message;


    toast.className =
        `toast show ${type}`;


    clearTimeout(
        toastTimer
    );


    toastTimer =
        setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            3000
        );

}