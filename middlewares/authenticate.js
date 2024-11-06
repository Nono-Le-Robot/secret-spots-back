const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken'); // Assurez-vous que jwt est bien importé
const app = express();

// Utiliser cookie-parser pour parser les cookies
app.use(cookieParser());

const authenticate = (req, res, next) => {
    // Récupérer le cookie "authToken"
    const token = req.cookies.authToken; // Correction ici : récupérer le cookie authToken depuis req.cookies

    // Vérifier si le token est présent
    if (!token) {
        return res.status(403).json({ error: 'Non authentifié. Aucun token trouvé.' });
    }

    try {
        // Vérification et décodage du token (en utilisant JWT)
        const decoded = jwt.verify(token, process.env.JWT_SECRET); // Utilisez la même clé secrète que lors de la génération du token
        req.user = decoded;  // Ajouter l'ID de l'utilisateur à la requête
        next(); // Passer à la route suivante (si le token est valide)
    } catch (error) {
        return res.status(403).json({ error: 'Token invalide ou expiré.' });
    }
};

module.exports = authenticate;

