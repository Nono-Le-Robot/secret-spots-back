// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const authenticate = require('../middlewares/authenticate');

dotenv.config();

const router = express.Router();

// Fonction utilitaire pour envoyer des erreurs
function sendError(res, message, statusCode = 400) {
    return res.status(statusCode).json({ error: message });
}

// Route d'inscription
router.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return sendError(res, 'Veuillez fournir un email et un mot de passe.');
    }

    try {
        // Vérification de l'existence de l'utilisateur
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return sendError(res, 'Cet email est déjà utilisé.');
        }

        // Hachage du mot de passe
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Créer un nouvel utilisateur
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();

        // Générer un token JWT
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Définir le token dans un cookie sécurisé
        res.cookie('authToken', token, {
            httpOnly: true,         // Empêche l'accès au cookie via JavaScript (protection contre XSS)
            secure: process.env.NODE_ENV === 'production', // En production, le cookie ne sera envoyé que sur HTTPS
            maxAge: 3600000,        // Le cookie expirera après 1 heure (en millisecondes)
            sameSite: 'Strict',     // Empêche l'envoi du cookie dans les requêtes cross-origin
        });

        // Réponse de succès
        return res.status(201).json({ message: 'Utilisateur créé avec succès.' });
    } catch (error) {
        console.error(error);
        return sendError(res, 'Erreur lors de l\'inscription.');
    }
});

// Route de connexion
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Trouver l'utilisateur par email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ error: 'Utilisateur non trouvé' });
        }

        // Vérification du mot de passe
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Mot de passe incorrect' });
        }

        // Création du token JWT
        const token = jwt.sign(
            { userId: user._id }, // Charge utile avec l'id de l'utilisateur
            process.env.JWT_SECRET,  // Utilisez la clé secrète du fichier .env
            { expiresIn: '1h' }   // Expiration du token
        );

        // Définir le token dans un cookie sécurisé
        res.cookie('authToken', token, {
            httpOnly: true,         // Empêche l'accès au cookie via JavaScript
            secure: process.env.NODE_ENV === 'production', // HTTPS en production
            maxAge: 3600000,        // Cookie expire après 1 heure
            sameSite: 'Strict',     // Sécurise les cookies cross-origin
        });

        // Réponse de succès
        
        res.json({ message: 'Connexion réussie.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Erreur du serveur' });
    }
});

router.post('/logout', (req, res) => {
console.log(req);

    res.clearCookie('authToken'); // Suppression du cookie contenant le token
    res.json({ message: 'Déconnexion réussie' });
});

router.get('/protected-route', authenticate, (req, res) => {


    res.json({ message: 'Accès autorisé à la route protégée', user: req.user });
});




module.exports = router;
